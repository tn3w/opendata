use crate::dns;
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr},
    os::fd::AsRawFd,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering::Relaxed},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpSocket, UdpSocket},
    sync::{Semaphore, mpsc, oneshot},
    time::{interval, sleep, timeout},
};
use tokio_rustls::{
    TlsConnector,
    rustls::{ClientConfig, RootCertStore, pki_types::ServerName},
};

const TIMEOUT: Duration = Duration::from_secs(4);
const OUTAGE: Duration = Duration::from_secs(2);
const SWEEP: Duration = Duration::from_millis(250);
const MAX_BACKOFF: Duration = Duration::from_secs(300);
const MAX_WINDOW: f64 = 32.0;
const MAX_ATTEMPTS: u8 = 3;
const MAX_SERVER_FAILURES: u8 = 2;
const EMPTY_CONFIRMATIONS: u8 = 2;
const CANARIES: [&str; 2] = ["8.8.8.8.in-addr.arpa", "1.0.0.10.in-addr.arpa"];

pub enum Answer {
    Missing,
    Names(Vec<String>),
    Failed,
}

struct Job {
    name: String,
    is_address: bool,
    attempts: u8,
    done: oneshot::Sender<Answer>,
}

#[derive(Clone, Copy, PartialEq)]
enum Scheme {
    Udp,
    Tcp,
    Tls,
}

struct Resolver {
    scheme: Scheme,
    address: Ipv4Addr,
    host: Option<String>,
    meter: Arc<Meter>,
}

#[derive(Default)]
pub struct Meter {
    pub label: String,
    pub replies: AtomicU64,
    pub timeouts: AtomicU64,
    pub window: AtomicU64,
}

enum Sink {
    Datagram(Arc<UdpSocket>),
    Stream(Box<dyn AsyncWrite + Send + Unpin>),
}

pub struct Pool {
    pub queries: AtomicU64,
    pub meters: Vec<Arc<Meter>>,
    any: (async_channel::Sender<Job>, async_channel::Receiver<Job>),
    stream: (async_channel::Sender<Job>, async_channel::Receiver<Job>),
    has_streams: bool,
    budget: Semaphore,
    last_reply: Mutex<Instant>,
    tls: TlsConnector,
}

impl Pool {
    pub fn start(list: &str, rate: usize) -> Arc<Self> {
        let resolvers: Vec<Resolver> = list.lines().flat_map(parse).collect();
        let roots =
            RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.enable_early_data = true;

        let pool = Arc::new(Self {
            queries: AtomicU64::new(0),
            meters: resolvers
                .iter()
                .map(|resolver| resolver.meter.clone())
                .collect(),
            any: async_channel::unbounded(),
            stream: async_channel::unbounded(),
            has_streams: resolvers
                .iter()
                .any(|resolver| resolver.scheme != Scheme::Udp),
            budget: Semaphore::new(0),
            last_reply: Mutex::new(Instant::now()),
            tls: TlsConnector::from(Arc::new(config)).early_data(true),
        });

        tokio::spawn(pool.clone().refill(rate));
        for resolver in resolvers {
            tokio::spawn(pool.clone().connection(resolver));
        }
        pool
    }

    pub async fn resolve(&self, name: String, is_address: bool) -> Answer {
        let (done, answer) = oneshot::channel();
        let job = Job {
            name,
            is_address,
            attempts: 0,
            done,
        };
        self.any.0.try_send(job).ok();
        answer.await.unwrap_or(Answer::Failed)
    }

    async fn refill(self: Arc<Self>, rate: usize) {
        let mut tick = interval(Duration::from_millis(10));
        loop {
            tick.tick().await;
            let missing = (rate / 10).saturating_sub(self.budget.available_permits());
            self.budget.add_permits(missing.min(rate / 100));
        }
    }

    async fn connection(self: Arc<Self>, resolver: Resolver) {
        let mut window = 2.0;
        let mut backoff = Duration::from_secs(1);

        loop {
            let started = Instant::now();
            self.session(&resolver, &mut window).await.ok();

            let healthy = started.elapsed() > TIMEOUT * 8;
            backoff = if healthy {
                Duration::from_secs(1)
            } else {
                (backoff * 2).min(MAX_BACKOFF)
            };
            window = (window / 2.0).max(1.0);
            resolver.meter.window.store(0, Relaxed);
            sleep(backoff).await;
        }
    }

    async fn session(&self, resolver: &Resolver, window: &mut f64) -> io::Result<()> {
        let (mut sink, mut replies) = self.connect(resolver).await?;
        check_canaries(&mut sink, &mut replies).await?;

        let mut pending: HashMap<u16, (Instant, Job)> = HashMap::new();
        let mut next_id = 0u16;
        let mut heard = Instant::now();
        let mut sweep = interval(SWEEP);

        let result = loop {
            let has_room = pending.len() < *window as usize;
            tokio::select! {
                packet = replies.recv() => {
                    let Some(packet) = packet else { break Ok(()) };
                    heard = Instant::now();
                    self.accept(resolver, &packet, &mut pending, window);
                }
                job = self.next_job(resolver.scheme), if has_room => {
                    self.budget.acquire().await.unwrap().forget();
                    while pending.contains_key(&next_id) {
                        next_id = next_id.wrapping_add(1);
                    }
                    let sent = sink.send(&dns::encode(next_id, &job.name)).await;
                    if let Err(error) = sent {
                        self.any.0.try_send(job).ok();
                        break Err(error);
                    }
                    self.queries.fetch_add(1, Relaxed);
                    pending.insert(next_id, (Instant::now(), job));
                }
                _ = sweep.tick() => {
                    if !pending.is_empty() && heard.elapsed() > TIMEOUT * 2 {
                        break Err(io::ErrorKind::TimedOut.into());
                    }
                    self.expire(resolver, &mut pending, window);
                }
            }
            resolver.meter.window.store(*window as u64, Relaxed);
        };

        for (_, job) in pending.into_values() {
            self.any.0.try_send(job).ok();
        }
        result
    }

    async fn next_job(&self, scheme: Scheme) -> Job {
        if scheme == Scheme::Udp {
            return self.any.1.recv().await.unwrap();
        }
        tokio::select! {
            biased;
            Ok(job) = self.stream.1.recv() => job,
            Ok(job) = self.any.1.recv() => job,
        }
    }

    fn accept(
        &self,
        resolver: &Resolver,
        packet: &[u8],
        pending: &mut HashMap<u16, (Instant, Job)>,
        window: &mut f64,
    ) {
        let Some(reply) = dns::decode(packet) else {
            return;
        };
        let is_awaited = |(_, job): &(Instant, Job)| job.name == reply.question;
        if !pending.get(&reply.id).is_some_and(is_awaited) {
            return;
        }

        let (_, job) = pending.remove(&reply.id).unwrap();
        *self.last_reply.lock().unwrap() = Instant::now();
        resolver.meter.replies.fetch_add(1, Relaxed);
        let needs_stream =
            reply.truncated && self.has_streams && resolver.scheme == Scheme::Udp;

        let is_doubtful = job.is_address && reply.names.is_empty();

        match reply.code {
            0 if needs_stream => drop(self.stream.0.try_send(job)),
            0 if is_doubtful => {
                *window = (*window - 1.0).max(1.0);
                self.retry(job, EMPTY_CONFIRMATIONS, Answer::Names(Vec::new()));
            }
            0 | dns::NXDOMAIN => {
                *window = (*window + 1.0 / *window).min(MAX_WINDOW);
                let is_missing = reply.code == dns::NXDOMAIN;
                let answer = if is_missing {
                    Answer::Missing
                } else {
                    Answer::Names(reply.names)
                };
                job.done.send(answer).ok();
            }
            dns::SERVFAIL => {
                *window = (*window - 1.0).max(1.0);
                self.retry(job, MAX_SERVER_FAILURES, Answer::Failed);
            }
            _ => {
                *window = (*window / 2.0).max(1.0);
                self.retry(job, MAX_ATTEMPTS, Answer::Failed);
            }
        }
    }

    fn expire(
        &self,
        resolver: &Resolver,
        pending: &mut HashMap<u16, (Instant, Job)>,
        window: &mut f64,
    ) {
        let is_outage = self.last_reply.lock().unwrap().elapsed() > OUTAGE;
        let expired: Vec<u16> = pending
            .iter()
            .filter(|(_, (sent, _))| sent.elapsed() > TIMEOUT)
            .map(|(id, _)| *id)
            .collect();
        if expired.is_empty() {
            return;
        }

        *window = (*window / 2.0).max(1.0);
        resolver
            .meter
            .timeouts
            .fetch_add(expired.len() as u64, Relaxed);
        for id in expired {
            let (_, job) = pending.remove(&id).unwrap();
            let limit = if is_outage { u8::MAX } else { MAX_ATTEMPTS };
            self.retry(job, limit, Answer::Failed);
        }
    }

    fn retry(&self, mut job: Job, limit: u8, verdict: Answer) {
        job.attempts = job.attempts.saturating_add(1).min(u8::MAX - 1);
        if job.attempts >= limit {
            job.done.send(verdict).ok();
            return;
        }
        self.any.0.try_send(job).ok();
    }

    async fn connect(
        &self,
        resolver: &Resolver,
    ) -> io::Result<(Sink, mpsc::Receiver<Vec<u8>>)> {
        let (sender, replies) = mpsc::channel(1024);
        if resolver.scheme == Scheme::Udp {
            let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
            socket.connect((resolver.address, 53)).await?;
            tokio::spawn(read_datagrams(socket.clone(), sender));
            return Ok((Sink::Datagram(socket), replies));
        }

        let port = if resolver.scheme == Scheme::Tls {
            853
        } else {
            53
        };
        let socket = TcpSocket::new_v4()?;
        enable_fast_open(&socket);
        let stream =
            timeout(TIMEOUT, socket.connect((resolver.address, port).into())).await??;
        if resolver.scheme == Scheme::Tcp {
            let (reader, writer) = stream.into_split();
            tokio::spawn(read_frames(reader, sender));
            return Ok((Sink::Stream(Box::new(writer)), replies));
        }

        let name = match &resolver.host {
            Some(host) => ServerName::try_from(host.clone()).map_err(io::Error::other)?,
            None => ServerName::IpAddress(IpAddr::V4(resolver.address).into()),
        };
        let stream = timeout(TIMEOUT, self.tls.connect(name, stream)).await??;
        let (reader, writer) = tokio::io::split(stream);
        tokio::spawn(read_frames(reader, sender));
        Ok((Sink::Stream(Box::new(writer)), replies))
    }
}

impl Sink {
    async fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        match self {
            Sink::Datagram(socket) => socket.send(packet).await.map(drop),
            Sink::Stream(writer) => {
                let mut frame = (packet.len() as u16).to_be_bytes().to_vec();
                frame.extend(packet);
                writer.write_all(&frame).await?;
                writer.flush().await
            }
        }
    }
}

fn enable_fast_open(socket: &TcpSocket) {
    let enabled: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN_CONNECT,
            (&raw const enabled).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

fn parse(line: &str) -> Vec<Resolver> {
    let mut fields = line
        .split('#')
        .next()
        .unwrap_or_default()
        .split_whitespace();
    let Some((scheme, target)) = fields.next().and_then(|url| url.split_once("://"))
    else {
        return Vec::new();
    };
    let scheme = match scheme {
        "udp" => Scheme::Udp,
        "tcp" => Scheme::Tcp,
        "tls" => Scheme::Tls,
        _ => return Vec::new(),
    };
    let (address, host) = match target.split_once('@') {
        Some((host, address)) => (address, Some(host.to_string())),
        None => (target, None),
    };
    let Ok(address) = address.parse() else {
        return Vec::new();
    };
    let connections = fields
        .next()
        .and_then(|count| count.parse().ok())
        .unwrap_or(1);

    (0..connections)
        .map(|_| Resolver {
            scheme,
            address,
            host: host.clone(),
            meter: Arc::new(Meter {
                label: line
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_string(),
                ..Meter::default()
            }),
        })
        .collect()
}

async fn check_canaries(
    sink: &mut Sink,
    replies: &mut mpsc::Receiver<Vec<u8>>,
) -> io::Result<()> {
    for (id, name) in CANARIES.iter().enumerate() {
        sink.send(&dns::encode(id as u16, name)).await?;
    }

    for _ in CANARIES {
        let packet = timeout(TIMEOUT, replies.recv()).await?;
        let reply = packet.as_deref().and_then(dns::decode);
        let is_honest = reply.is_some_and(|reply| match reply.id {
            0 => reply.names == ["dns.google"],
            _ => reply.code == dns::NXDOMAIN,
        });
        if !is_honest {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
    Ok(())
}

async fn read_datagrams(socket: Arc<UdpSocket>, sender: mpsc::Sender<Vec<u8>>) {
    let mut buffer = [0; 4096];
    loop {
        let length = tokio::select! {
            _ = sender.closed() => return,
            length = socket.recv(&mut buffer) => length,
        };
        let Ok(length) = length else { return };
        if sender.send(buffer[..length].to_vec()).await.is_err() {
            return;
        }
    }
}

async fn read_frames(mut reader: impl AsyncRead + Unpin, sender: mpsc::Sender<Vec<u8>>) {
    loop {
        let mut packet = Vec::new();
        let frame = async {
            let length = reader.read_u16().await?;
            packet.resize(length as usize, 0);
            reader.read_exact(&mut packet).await
        };
        let is_read = tokio::select! {
            _ = sender.closed() => return,
            frame = frame => frame.is_ok(),
        };
        if !is_read || sender.send(packet).await.is_err() {
            return;
        }
    }
}
