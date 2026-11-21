use crate::{credential, public};
use iscrawl::{crawler_info, is_crawler};
use listenfd::ListenFd;
use rdns::scan;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fs,
    io::{BufRead, BufReader},
    net::{IpAddr, Ipv6Addr},
    os::unix::net::{UnixListener, UnixStream},
    path::Path,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const DAY: u64 = 86400;
const PUBLISH_INTERVAL: Duration = Duration::from_secs(300);
const MAX_USER_AGENTS: usize = 8;
const MAX_USER_AGENT_LENGTH: usize = 256;
const OWN_CLIENTS: &[&str] = &["Shelf ("];
const FETCHER_TAGS: &[&str] = &[
    "social-preview",
    "feed-reader",
    "ai-fetcher",
    "archiver",
    "monitoring",
];

type Table = BTreeMap<String, Vec<String>>;

#[derive(Deserialize, Default)]
struct Rules {
    paths: Table,
    queries: Table,
    scanners: Vec<String>,
    methods: Vec<String>,
}

#[derive(Deserialize)]
struct Entry {
    request: Option<Request>,
    report: Option<Report>,
}

#[derive(Serialize, Deserialize)]
pub struct Report {
    pub client_ip: IpAddr,
    pub categories: BTreeSet<String>,
}

#[derive(Deserialize)]
struct Request {
    client_ip: IpAddr,
    method: String,
    uri: String,
    headers: HashMap<String, Vec<String>>,
}

#[derive(Serialize, Deserialize, Default)]
struct Abuser {
    first_seen: u64,
    last_seen: u64,
    requests: u64,
    categories: BTreeSet<String>,
}

#[derive(Serialize, Deserialize, Default)]
struct Crawler {
    first_seen: u64,
    last_seen: u64,
    requests: u64,
    robots_txt: bool,
    user_agents: BTreeSet<String>,
    tags: BTreeSet<String>,
    ptr: Vec<String>,
    verified: Option<bool>,
}

#[derive(Default)]
struct State {
    abusers: BTreeMap<String, Abuser>,
    crawlers: BTreeMap<String, Crawler>,
    rules: Rules,
    beacon: String,
    own_networks: HashSet<String>,
    published: Option<Instant>,
}

pub fn run() {
    let mut descriptors = ListenFd::from_env();
    let listeners: Vec<UnixListener> = (0..descriptors.len())
        .map(|index| descriptors.take_unix_listener(index).ok().flatten())
        .map(|listener| listener.expect("systemd passes unix sockets"))
        .collect();
    let mut crawlers: BTreeMap<String, Crawler> =
        load(&public("crawlers").join("ips.json"));
    for (network, crawler) in &mut crawlers {
        crawler.refresh(network);
    }
    let state = Arc::new(Mutex::new(State {
        abusers: load(&public("abuse").join("ips.json")),
        crawlers,
        rules: serde_json::from_str(&credential("rules")).expect("rules are valid"),
        beacon: credential("beacon").trim().to_string(),
        ..State::default()
    }));

    let accepting: Vec<_> = listeners
        .into_iter()
        .map(|listener| {
            let state = state.clone();
            thread::spawn(move || accept(listener, &state))
        })
        .collect();
    for thread in accepting {
        thread.join().unwrap();
    }
}

fn accept(listener: UnixListener, state: &Arc<Mutex<State>>) {
    for stream in listener.incoming().flatten() {
        let state = state.clone();
        thread::spawn(move || follow(stream, &state));
    }
}

fn follow(stream: UnixStream, state: &Mutex<State>) {
    for line in BufReader::new(stream).lines().map_while(Result::ok) {
        let Ok(entry) = serde_json::from_str::<Entry>(&line) else {
            continue;
        };
        let mut state = state.lock().unwrap();
        if let Some(report) = entry.report {
            state.reported(report, today());
        }
        let Some(request) = entry.request else {
            continue;
        };
        let is_checked = state.observe(&request, today());
        let is_due = state
            .published
            .is_none_or(|published| published.elapsed() >= PUBLISH_INTERVAL);
        if is_checked && is_due {
            state.publish();
        }
    }
}

fn today() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    now / DAY * DAY
}

fn load<Record: DeserializeOwned>(path: &Path) -> BTreeMap<String, Record> {
    let content = fs::read_to_string(path).unwrap_or_default();
    serde_json::from_str(&content).unwrap_or_default()
}

fn network(address: IpAddr) -> Option<String> {
    match address.to_canonical() {
        IpAddr::V4(address) => {
            let is_public = !address.is_private()
                && !address.is_loopback()
                && !address.is_link_local()
                && !address.is_unspecified();
            is_public.then(|| address.to_string())
        }
        IpAddr::V6(address) => {
            let [first, second, third, fourth, ..] = address.segments();
            let prefix = Ipv6Addr::new(first, second, third, fourth, 0, 0, 0, 0);
            (first & 0xE000 == 0x2000).then(|| format!("{prefix}/64"))
        }
    }
}

fn is_fetcher(agent: &str) -> bool {
    let tags = crawler_info(agent).map_or(&[][..], |info| &info.tags);
    tags.iter().any(|tag| FETCHER_TAGS.contains(&tag.as_str()))
}

fn decode(query: &str) -> String {
    let mut bytes = Vec::with_capacity(query.len());
    let mut rest = query.as_bytes();

    while let [byte, tail @ ..] = rest {
        let escaped = tail
            .get(..2)
            .filter(|_| *byte == b'%')
            .and_then(|digits| str::from_utf8(digits).ok())
            .and_then(|digits| u8::from_str_radix(digits, 16).ok());
        bytes.push(escaped.unwrap_or(if *byte == b'+' { b' ' } else { *byte }));
        rest = if escaped.is_some() { &tail[2..] } else { tail };
    }
    String::from_utf8_lossy(&bytes).to_lowercase()
}

fn matching<'a>(table: &'a Table, text: &str) -> impl Iterator<Item = &'a String> {
    table
        .iter()
        .filter(|(_, needles)| needles.iter().any(|needle| text.contains(needle)))
        .map(|(category, _)| category)
}

impl Rules {
    fn categories(&self, request: &Request, agent: &str) -> BTreeSet<String> {
        let (path, query) = request.uri.split_once('?').unwrap_or((&request.uri, ""));
        let (path, query) = (path.to_lowercase(), decode(query));
        let agent = agent.to_lowercase();
        let is_scanner = self.scanners.iter().any(|scanner| agent.contains(scanner));
        let is_odd_method = self.methods.contains(&request.method);

        matching(&self.paths, &path)
            .chain(matching(&self.queries, &query))
            .cloned()
            .chain(is_scanner.then(|| "scanner".into()))
            .chain(is_odd_method.then(|| "method".into()))
            .collect()
    }
}

impl State {
    fn observe(&mut self, request: &Request, today: u64) -> bool {
        let Some(network) = network(request.client_ip) else {
            return false;
        };
        let header = |name: &str| {
            let values = request.headers.get(name);
            values
                .and_then(|values| values.first())
                .map_or("", String::as_str)
        };
        let agent = header("User-Agent");
        let path = request.uri.split('?').next().unwrap_or_default();

        if !self.beacon.is_empty() && agent == self.beacon {
            self.abusers.remove(&network);
            self.crawlers.remove(&network);
            self.own_networks.insert(network);
            return request.client_ip.to_canonical().is_ipv4();
        }
        if self.own_networks.contains(&network) {
            return false;
        }

        let is_scripted = matches!(header("Sec-Fetch-Site"), "" | "none");
        let categories = self.rules.categories(request, agent);
        if is_scripted && !is_fetcher(agent) && !categories.is_empty() {
            self.list_abuser(network.clone(), categories, today);
        }

        let is_own_client = OWN_CLIENTS.iter().any(|client| agent.starts_with(client));
        if is_own_client || !is_crawler(agent) {
            return false;
        }
        let is_new = !self.crawlers.contains_key(&network);
        let crawler = self.crawlers.entry(network).or_default();
        crawler.record(agent, path, today);
        if is_new {
            crawler.verify(request.client_ip, agent);
        }
        false
    }

    fn reported(&mut self, report: Report, today: u64) {
        let Some(network) = network(report.client_ip) else {
            return;
        };
        if !self.own_networks.contains(&network) {
            self.list_abuser(network, report.categories, today);
        }
    }

    fn list_abuser(&mut self, network: String, categories: BTreeSet<String>, today: u64) {
        let abuser = self.abusers.entry(network).or_default();
        if abuser.requests == 0 {
            abuser.first_seen = today;
        }
        abuser.last_seen = today;
        abuser.requests += 1;
        abuser.categories.extend(categories);
    }

    fn publish(&mut self) {
        self.published = Some(Instant::now());
        write_list(&public("abuse"), &self.abusers);
        write_list(&public("crawlers"), &self.crawlers);
    }
}

impl Crawler {
    fn record(&mut self, agent: &str, path: &str, today: u64) {
        if self.requests == 0 {
            self.first_seen = today;
        }
        self.last_seen = today;
        self.requests += 1;
        self.robots_txt |= path == "/robots.txt";

        if self.user_agents.len() < MAX_USER_AGENTS {
            let agent = agent.chars().take(MAX_USER_AGENT_LENGTH).collect();
            self.user_agents.insert(agent);
        }
        if let Some(info) = crawler_info(agent) {
            self.tags.extend(info.tags.iter().cloned());
        }
    }

    fn refresh(&mut self, network: &str) {
        let Ok(address) = network.parse() else {
            return;
        };
        let has_suffixes = |agent: &&String| {
            crawler_info(agent).is_some_and(|info| !info.rdns.is_empty())
        };
        let agent = self.user_agents.iter().find(has_suffixes);
        let agent = agent
            .or(self.user_agents.first())
            .cloned()
            .unwrap_or_default();
        self.verify(address, &agent);
    }

    fn verify(&mut self, address: IpAddr, agent: &str) {
        let IpAddr::V4(address) = address.to_canonical() else {
            return;
        };
        self.ptr = scan::lookup(&public("rdns"), address);
        self.verified = None;

        let suffixes = crawler_info(agent).map_or(&[][..], |info| &info.rdns);
        if self.ptr.is_empty() || suffixes.is_empty() {
            return;
        }
        let is_claimed =
            |name: &String| suffixes.iter().any(|suffix| name.ends_with(suffix));
        self.verified = Some(self.ptr.iter().any(is_claimed));
    }
}

fn write_list<Record: Serialize>(directory: &Path, records: &BTreeMap<String, Record>) {
    let networks: Vec<&str> = records.keys().map(String::as_str).collect();
    let details = serde_json::to_vec(records).unwrap();

    let written = scan::replace(
        &directory.join("ips.txt"),
        (networks.join("\n") + "\n").as_bytes(),
    )
    .and_then(|_| scan::replace(&directory.join("ips.json"), &details));
    if let Err(error) = written {
        eprintln!("cannot publish {}: {error}", directory.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BROWSER: &str =
        "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0";

    fn request(address: &str, uri: &str, headers: &[(&str, &str)]) -> Request {
        let headers = headers
            .iter()
            .map(|(name, value)| (name.to_string(), vec![value.to_string()]));
        Request {
            client_ip: address.parse().unwrap(),
            method: "GET".into(),
            uri: uri.into(),
            headers: headers.collect(),
        }
    }

    fn kinds(state: &State, network: &str) -> Vec<String> {
        state.abusers[network].categories.iter().cloned().collect()
    }

    fn listed<Record>(records: &BTreeMap<String, Record>) -> Vec<&str> {
        records.keys().map(String::as_str).collect()
    }

    fn state() -> State {
        let rules = include_str!("../rules.example.json");
        State {
            rules: serde_json::from_str(rules).unwrap(),
            ..State::default()
        }
    }

    #[test]
    fn ordinary_visitors_leave_no_trace() {
        let mut state = state();
        let pages = [
            "/",
            "/img/a.avif",
            "/b/10/en",
            "/s?q=the+union+of+select+few",
        ];
        for uri in pages {
            let visit = request("203.0.113.5", uri, &[("User-Agent", BROWSER)]);
            state.observe(&visit, DAY);
        }

        assert!(state.abusers.is_empty() && state.crawlers.is_empty());
    }

    #[test]
    fn attacks_are_listed_but_lured_browsers_are_not() {
        let mut state = state();
        let browser = [("User-Agent", BROWSER)];
        let lured = [("User-Agent", BROWSER), ("Sec-Fetch-Site", "cross-site")];
        let scanner = [("User-Agent", "Mozilla/5.0 zgrab/0.x")];
        state.observe(&request("203.0.113.5", "/.env", &lured), DAY);
        state.observe(&request("203.0.113.6", "/wp-login.php", &browser), DAY);
        state.observe(
            &request("203.0.113.7", "/s?q=1%27+UNION+SELECT+1", &browser),
            DAY,
        );
        state.observe(&request("203.0.113.8", "/", &scanner), DAY);
        state.observe(&request("192.168.0.7", "/.git/config", &[]), DAY);
        state.observe(&request("2001:db8:1:2:3:4:5:6", "/.git/config", &[]), DAY);

        let expected = [
            "2001:db8:1:2::/64",
            "203.0.113.6",
            "203.0.113.7",
            "203.0.113.8",
        ];
        assert_eq!(listed(&state.abusers), expected);
        assert_eq!(kinds(&state, "203.0.113.6"), ["php", "wordpress"]);
        assert_eq!(kinds(&state, "203.0.113.7"), ["injection"]);
        assert_eq!(kinds(&state, "203.0.113.8"), ["scanner"]);
    }

    #[test]
    fn fetchers_sent_a_link_are_crawlers_not_attackers() {
        let mut state = state();
        let proxy = [("User-Agent", "Mozilla/5.0 (via ggpht.com GoogleImageProxy)")];
        let slack = [("User-Agent", "Slackbot-LinkExpanding 1.0")];
        state.observe(&request("203.0.113.5", "/wp-login.php", &proxy), DAY);
        state.observe(&request("203.0.113.6", "/.env", &slack), DAY);

        assert!(state.abusers.is_empty());
        assert_eq!(listed(&state.crawlers), ["203.0.113.5", "203.0.113.6"]);
    }

    #[test]
    fn every_non_browser_is_listed_except_own_clients() {
        let mut state = State::default();
        let bot = [(
            "User-Agent",
            "Googlebot/2.1 (+http://www.google.com/bot.html)",
        )];
        let app = [("User-Agent", "Shelf (https://github.com/tn3w/Shelf)")];
        state.observe(
            &request("203.0.113.5", "/", &[("User-Agent", "curl/8.0")]),
            DAY,
        );
        state.observe(&request("203.0.113.6", "/robots.txt", &bot), DAY);
        state.observe(&request("203.0.113.7", "/api/v1/search", &app), DAY);
        state.observe(
            &request("203.0.113.8", "/", &[("User-Agent", BROWSER)]),
            DAY,
        );

        assert_eq!(listed(&state.crawlers), ["203.0.113.5", "203.0.113.6"]);
        assert!(state.crawlers["203.0.113.6"].tags.contains("search-engine"));
        assert!(state.crawlers["203.0.113.6"].robots_txt);
    }

    #[test]
    fn own_addresses_are_dropped_and_never_listed_again() {
        let mut state = State {
            beacon: "secret".into(),
            ..State::default()
        };
        let curl = [("User-Agent", "curl/8.0")];
        let beacon = [("User-Agent", "secret")];
        state.observe(&request("203.0.113.5", "/.env", &curl), DAY);
        state.observe(&request("2001:db8:1:2::9", "/", &curl), DAY);
        state.observe(&request("203.0.113.6", "/", &curl), DAY);

        assert!(!state.observe(&request("2001:db8:1:2::1", "/", &beacon), DAY));
        assert!(state.observe(&request("203.0.113.5", "/", &beacon), DAY));
        state.observe(&request("203.0.113.5", "/.env", &curl), DAY);
        state.observe(&request("2001:db8:1:2::7", "/", &curl), DAY);

        assert_eq!(listed(&state.crawlers), ["203.0.113.6"]);
        assert!(state.abusers.is_empty());
    }

    #[test]
    fn reports_are_listed_except_own_and_private_addresses() {
        let mut state = State {
            beacon: "secret".into(),
            ..State::default()
        };
        state.observe(
            &request("203.0.113.5", "/", &[("User-Agent", "secret")]),
            DAY,
        );
        let report = |address: &str, categories: &[&str]| Report {
            client_ip: address.parse().unwrap(),
            categories: categories
                .iter()
                .map(|category| category.to_string())
                .collect(),
        };
        state.reported(report("::ffff:198.51.100.4", &["a"]), DAY);
        state.reported(report("198.51.100.4", &["a", "b"]), DAY);
        state.reported(report("203.0.113.5", &["a"]), DAY);
        state.reported(report("10.0.0.3", &["a"]), DAY);

        assert_eq!(listed(&state.abusers), ["198.51.100.4"]);
        assert_eq!(kinds(&state, "198.51.100.4"), ["a", "b"]);
        assert_eq!(state.abusers["198.51.100.4"].requests, 2);
    }
}
