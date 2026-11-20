use crate::{
    dns::reverse_name,
    resolver::{Answer, Pool},
};
use futures_util::{StreamExt, future::ready, stream};
use liblzma::{stream::MtStreamBuilder, write::XzEncoder};
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    env,
    fmt::Write as _,
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Write as _},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering::Relaxed},
    },
    thread::available_parallelism,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::OnceCell, task::spawn_blocking, time::sleep};

const PASS_INTERVAL: u64 = 30 * 86400;
const CONCURRENT_BLOCKS: usize = 256;
const QUERIES_PER_BLOCK: usize = 32;
const COMPRESSION_LEVEL: i32 = 19;
const FULL_PRESET: u32 = 6;
const SPREAD: u16 = 40503;
const MISSING_CONFIRMATIONS: usize = 2;

struct Scan {
    pool: Arc<Pool>,
    public: PathBuf,
    state: PathBuf,
    done: Mutex<HashSet<u16>>,
    top_levels: [OnceCell<bool>; 256],
    started: AtomicU64,
    records: AtomicU64,
    earlier_queries: AtomicU64,
}

pub async fn run(public: PathBuf) {
    let variable = |name: &str, default: &str| env::var(name).unwrap_or(default.into());
    let list = fs::read_to_string(variable("RDNS_RESOLVERS", "resolvers.txt"))
        .expect("resolver list is readable");
    let rate = variable("RDNS_RATE", "4000")
        .parse()
        .expect("rate is a number");
    let state = PathBuf::from(variable("STATE_DIRECTORY", "state"));
    let done = fs::read_to_string(state.join("done")).unwrap_or_default();
    let stats = fs::read_to_string(public.join("stats.json")).unwrap_or_default();
    let stats: Value = serde_json::from_str(&stats).unwrap_or_default();

    let scan = Arc::new(Scan {
        pool: Pool::start(&list, rate),
        public,
        state,
        done: Mutex::new(done.lines().flat_map(str::parse).collect()),
        top_levels: [const { OnceCell::const_new() }; 256],
        started: AtomicU64::new(stats["started"].as_u64().unwrap_or_else(now)),
        records: AtomicU64::new(stats["records"].as_u64().unwrap_or(0)),
        earlier_queries: AtomicU64::new(stats["queries"].as_u64().unwrap_or(0)),
    });

    tokio::spawn(scan.clone().report());
    loop {
        scan.pass().await;
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn is_scannable(block: &u16) -> bool {
    let first = block >> 8;
    (1..224).contains(&first) && first != 10 && first != 127
}

impl Scan {
    async fn pass(&self) {
        let blocks: Vec<u16> = (0..=u16::MAX)
            .map(|index| index.wrapping_mul(SPREAD))
            .filter(is_scannable)
            .filter(|block| !self.done.lock().unwrap().contains(block))
            .collect();

        stream::iter(blocks)
            .for_each_concurrent(CONCURRENT_BLOCKS, |block| self.block(block))
            .await;
        self.write_stats();
        self.write_full().await;

        let next_pass = self.started.load(Relaxed) + PASS_INTERVAL;
        sleep(Duration::from_secs(next_pass.saturating_sub(now()))).await;

        fs::remove_file(self.state.join("done")).ok();
        self.done.lock().unwrap().clear();
        self.started.store(now(), Relaxed);
        self.records.store(0, Relaxed);
        self.earlier_queries.store(0, Relaxed);
        self.pool.queries.store(0, Relaxed);
    }

    async fn write_full(&self) {
        let path = self.public.join("v4/all.tsv.xz");
        let started = UNIX_EPOCH + Duration::from_secs(self.started.load(Relaxed));
        let modified = fs::metadata(&path).and_then(|metadata| metadata.modified());
        if modified.is_ok_and(|time| time >= started) {
            return;
        }
        let public = self.public.join("v4");
        spawn_blocking(move || full(&public, &path))
            .await
            .unwrap()
            .expect("full file is writable");
    }

    async fn block(&self, block: u16) {
        let [first, second] = block.to_be_bytes();
        let has_top_level = *self.top_levels[first as usize]
            .get_or_init(|| self.exists(vec![first], true))
            .await;

        let mut lines = String::new();
        if has_top_level && self.exists(vec![first, second], true).await {
            lines = self.hosts(first, second).await;
        }
        self.records
            .fetch_add(lines.lines().count() as u64, Relaxed);

        let path = self.public.join(format!("v4/{first}/{second}.tsv.zst"));
        spawn_blocking(move || store(&path, lines.as_bytes()))
            .await
            .unwrap()
            .expect("block file is writable");
        self.finish(block);
    }

    async fn exists(&self, octets: Vec<u8>, exists_on_failure: bool) -> bool {
        for _ in 0..MISSING_CONFIRMATIONS {
            match self.pool.resolve(reverse_name(&octets), false).await {
                Answer::Names(_) => return true,
                Answer::Failed => return exists_on_failure,
                Answer::Missing => continue,
            }
        }
        false
    }

    async fn hosts(&self, first: u8, second: u8) -> String {
        let thirds: Vec<u8> = stream::iter(0..=255)
            .map(|third| async move {
                let is_served = self.exists(vec![first, second, third], false).await;
                is_served.then_some(third)
            })
            .buffer_unordered(QUERIES_PER_BLOCK)
            .filter_map(ready)
            .collect()
            .await;

        let addresses = thirds.iter().flat_map(|&third| {
            (0..=255).map(move |fourth| [first, second, third, fourth])
        });
        let mut found: Vec<([u8; 4], Vec<String>)> = stream::iter(addresses)
            .map(|octets| async move {
                match self.pool.resolve(reverse_name(&octets), true).await {
                    Answer::Names(names) if !names.is_empty() => Some((octets, names)),
                    _ => None,
                }
            })
            .buffer_unordered(QUERIES_PER_BLOCK)
            .filter_map(ready)
            .collect()
            .await;
        found.sort();

        let mut lines = String::new();
        for (octets, mut names) in found {
            names.sort();
            names.dedup();
            for name in names {
                writeln!(lines, "{}\t{name}", Ipv4Addr::from(octets)).unwrap();
            }
        }
        lines
    }

    fn finish(&self, block: u16) {
        self.done.lock().unwrap().insert(block);
        let mut log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.state.join("done"))
            .expect("state directory is writable");
        writeln!(log, "{block}").expect("state directory is writable");
    }

    async fn report(self: Arc<Self>) {
        loop {
            sleep(Duration::from_secs(60)).await;
            self.write_stats();
        }
    }

    fn write_stats(&self) {
        let blocks_done = self.done.lock().unwrap().len();
        let queries =
            self.earlier_queries.load(Relaxed) + self.pool.queries.load(Relaxed);
        let stats = json!({
            "started": self.started.load(Relaxed),
            "updated": now(),
            "blocks_done": blocks_done,
            "blocks_total": (0..=u16::MAX).filter(is_scannable).count(),
            "addresses_covered": blocks_done as u64 * 65536,
            "queries": queries,
            "records": self.records.load(Relaxed),
        });
        replace(
            &self.public.join("stats.json"),
            stats.to_string().as_bytes(),
        )
        .ok();

        let files: String = (0..=u16::MAX)
            .map(|block| block.to_be_bytes())
            .map(|[first, second]| format!("{first}/{second}.tsv.zst\n"))
            .filter(|file| self.public.join("v4").join(file.trim_end()).exists())
            .collect();
        replace(&self.public.join("v4/files.txt"), files.as_bytes()).ok();

        let mut meters = String::from("resolver\twindow\treplies\ttimeouts\n");
        for meter in &self.pool.meters {
            let counts = [&meter.window, &meter.replies, &meter.timeouts]
                .map(|count| count.load(Relaxed));
            writeln!(
                meters,
                "{}\t{}\t{}\t{}",
                meter.label, counts[0], counts[1], counts[2]
            )
            .unwrap();
        }
        replace(&self.state.join("resolvers.tsv"), meters.as_bytes()).ok();
    }
}

pub fn lookup(root: &Path, address: Ipv4Addr) -> Vec<String> {
    let [first, second, ..] = address.octets();
    let Ok(file) = File::open(root.join(format!("v4/{first}/{second}.tsv.zst"))) else {
        return Vec::new();
    };

    let prefix = format!("{address}\t");
    let lines = zstd::decode_all(file).unwrap_or_default();
    String::from_utf8_lossy(&lines)
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix))
        .map(String::from)
        .collect()
}

pub fn replace(path: &Path, content: &[u8]) -> io::Result<()> {
    let draft = path.with_extension("new");
    fs::create_dir_all(path.parent().unwrap())?;
    fs::write(&draft, content)?;
    fs::rename(draft, path)
}

fn full(public: &Path, path: &Path) -> io::Result<()> {
    let threads = available_parallelism().map_or(1, |count| count.get() as u32);
    let stream = MtStreamBuilder::new()
        .preset(FULL_PRESET)
        .threads(threads)
        .encoder()?;
    let draft = path.with_extension("new");
    let mut encoder =
        XzEncoder::new_stream(BufWriter::new(File::create(&draft)?), stream);
    for name in fs::read_to_string(public.join("files.txt"))?.lines() {
        let file = File::open(public.join(name))?;
        io::copy(&mut zstd::Decoder::new(file)?, &mut encoder)?;
    }
    encoder.finish()?.flush()?;
    fs::rename(draft, path)
}

fn store(path: &Path, lines: &[u8]) -> io::Result<()> {
    if lines.is_empty() {
        fs::remove_file(path).ok();
        return Ok(());
    }
    replace(path, &zstd::encode_all(lines, COMPRESSION_LEVEL)?)
}
