# opendata

Open network data from one home server, free under [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/).
Docs and live lookups: [data.tn3w.dev](https://data.tn3w.dev).

| file | content | updated |
| --- | --- | --- |
| `rdns-v4.tsv.xz` | every IPv4 PTR record, `address<TAB>hostname`, sorted | after each 30-day pass |
| `abuse.txt` / `.json` | addresses that attacked the server's websites | hourly |
| `crawlers.txt` / `.json` | non-browser clients, with user agents, PTR and verification | hourly |

```sh
gh release download data -R tn3w/opendata -p 'rdns-v4.tsv.xz'
curl -LO https://github.com/tn3w/opendata/releases/download/data/abuse.txt
```

## Code

| path | does |
| --- | --- |
| `rdns/` | `rdns scan <dir>`: walks `in-addr.arpa`; NXDOMAIN on a /8, /16 or /24 prunes it, so most of IPv4 is never queried one address at a time. UDP, pipelined TCP and DoT to public resolvers, a congestion window per connection. `rdns lookup <dir> <ip>` answers from the result. |
| `src/` | `opendata api` (lookups over a unix socket), `opendata watch` (abuse and crawler lists from Caddy's JSON access log) |
| `units/` | systemd units and the upload script |

`opendata watch` reads its abuse rules from a private file, so attack tools cannot learn
them. `rules.example.json` shows the format.

```sh
cargo build --release
RDNS_RESOLVERS=resolvers.txt target/release/rdns scan public/rdns
```

Code is MIT, data is CC0.
