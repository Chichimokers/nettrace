# NetTrace

NetTrace is a Windows console tool that watches one executable and records what
that program did on the network: which process instances ran, which TCP/UDP
endpoints they used, and which DNS queries they issued. Everything is stored in
a local SQLite database, so history survives reboots and can be filtered or
exported later.

It is an **observation tool**. It does not modify the system, does not intercept
TLS or HTTP, does not read packet payloads, and has no GUI.

- Version: `0.1.0`
- Platform: Windows 10/11 x64
- Language: Go 1.27.1 or newer (the module declares `go 1.27.1`)
- No CGO, no Npcap, no driver to install

## What it collects

| Area | Primary source | What is stored |
| --- | --- | --- |
| Processes | ETW `Microsoft-Windows-Kernel-Process`, Toolhelp32 snapshots | PID, parent PID, image path, start/end time, exit code when known, `captured_from_start` or `already_running` |
| TCP/UDP | ETW `Microsoft-Windows-Kernel-Network`; IP Helper tables as fallback | Protocol, IPv4/IPv6, local/remote endpoint, state, event type, bytes, occurrences, source |
| DNS | ETW `Microsoft-Windows-DNS-Client` event 3008 | Query name, type, status, answers when decodable, calling PID if it belongs to a monitored instance |

Capture is started **before** NetTrace waits for the target. Activity that
happened before the capture began is never invented: a process that is already
running is stored as `already_running`, and its earlier connections or DNS
queries are not recoverable.

## Requirements and privileges

- Windows 10 or Windows 11, x64.
- **Administrator is required for the kernel ETW providers**
  (`Kernel-Network` and `Kernel-Process`). Run the terminal or the .exe with
  "Run as administrator" to get state-change events, short-lived connections and
  ETW process start/exit events.
- Without elevation:
  - `Microsoft-Windows-DNS-Client` ETW usually still works and DNS queries are
    recorded.
  - Network and process data fall back to polling `GetExtendedTcpTable`,
    `GetExtendedUdpTable` and Toolhelp32.
  - The session is stored with per-provider source health, and both the console
    and `status` report the ETW state as `partial` or `no`. NetTrace never claims
    full coverage when a provider was denied.
- Building from source requires Go 1.27.1+. A separately provided release
  binary does not need Go installed to run.

The exact source behavior, event IDs and fallback details are documented in
[docs/SOURCES.md](docs/SOURCES.md).

## Build

From PowerShell, in this directory:

```powershell
cd .
go build -trimpath -ldflags "-s -w" -o nettrace.exe .\cmd\nettrace
.\nettrace.exe version
```

The result is a self-contained executable. Build outputs are ignored by
[.gitignore](.gitignore) and are not included in the source repository.

### Install

There is no installer and no service. Build `nettrace.exe` first, then copy it
anywhere you want and call it with its full path, or add that folder to `PATH`
for the current user:

```powershell
$dest = "$env:LOCALAPPDATA\NetTrace"
New-Item -ItemType Directory -Force -Path $dest | Out-Null
Copy-Item .\nettrace.exe $dest -Force
$env:Path += ";$dest"          # current session only
[Environment]::SetEnvironmentVariable(
  "Path", [Environment]::GetEnvironmentVariable("Path", "User") + ";$dest", "User")
nettrace version
```

Uninstall by deleting `nettrace.exe` and, if you no longer need the history,
`%LOCALAPPDATA%\NetTrace`. Nothing is written outside the database, the config
file and the WAL files next to them.

## Quick start

Open an **Administrator** PowerShell for full capture:

```powershell
cd .

# Monitor one executable by full path (every instance of that file).
.\nettrace.exe monitor --exe "D:\Games\StarCraft II\SC2_x64.exe"

# Monitor every process with a given file name, for 10 minutes.
.\nettrace.exe monitor --name "game.exe" --duration 10m

# Fast, non-elevated mode: sampled TCP/UDP tables, no DNS.
.\nettrace.exe monitor --name "game.exe" --no-etw --verbose
```

Press `Ctrl+C` (or let `--duration` expire) to stop. The summary shows where the
database is and which sources were active. Inspect the result with:

```powershell
.\nettrace.exe history
.\nettrace.exe status
.\nettrace.exe export --format json --out session.json
```

## Commands

### `monitor`

```
nettrace monitor --exe "C:\path\program.exe" [flags]
nettrace monitor --name "program.exe" [flags]
```

| Flag | Meaning |
| --- | --- |
| `--exe PATH` | Match by full image path after resolving the file. A bare name is accepted and treated as a name match with a warning. |
| `--name NAME` | Match by executable file name (all instances). |
| `--duration D` | Stop automatically, e.g. `30s`, `5m`, `1h`. |
| `--no-etw` | Do not start ETW; sample IP Helper + Toolhelp32. DNS is not collected. |
| `--poll-interval D` | Process/connection polling interval. Default 2s, minimum 250ms. |
| `--verbose` | Also print TCP data, UDP datagram, retransmit and sampled rows. |
| `--quiet` | Do not print individual events. |
| `--dns-unattributed` | Store DNS queries whose PID is not a monitored instance, marked unattributed. |
| `--db PATH` | SQLite database (default `%LOCALAPPDATA%\NetTrace\nettrace.db`). |
| `--config PATH` | Config file (default `%LOCALAPPDATA%\NetTrace\config.json`). |

Only one of `--exe` and `--name` may be used. A path target must exist; a name
target may be started later. Multiple instances of the same executable are
tracked independently, including PID reuse.

### `history`

Shows sessions, processes, connections and DNS rows. Filters apply to every
section; use `--json` for the same JSON shape as `export --format json`.

```powershell
.\nettrace.exe history
.\nettrace.exe history --session 3
.\nettrace.exe history --exe "SC2_x64.exe" --limit 50
.\nettrace.exe history --exe "D:\Games\StarCraft II\SC2_x64.exe"
.\nettrace.exe history --pid 1234
.\nettrace.exe history --since "2026-10-26 10:00:00" --until "2026-10-26 11:00:00"
.\nettrace.exe history --ip 1.1.1.1 --port 443 --proto tcp
.\nettrace.exe history --event connect
.\nettrace.exe history --domain battle.net
.\nettrace.exe history --json
```

| Flag | Meaning |
| --- | --- |
| `--exe`, `--name` | Executable name (exact, case-insensitive) or directory-qualified path (exact or suffix). |
| `--pid N` | Process ID. |
| `--session N` | Monitoring session ID. |
| `--since`, `--until` | RFC3339, `2006-01-02 15:04:05`, or `2006-01-02`. Local time is assumed. |
| `--ip ADDR` | Local or remote address. |
| `--port N` | Local or remote port. |
| `--proto tcp\|udp` | Protocol. |
| `--domain NAME` | DNS name or suffix (`example.com` also matches `api.example.com`). |
| `--event TYPE` | Connection `event_type` (`connect`, `establish`, `close`, `data`, `observed`, ...). |
| `--dns` | Show only the DNS section. |
| `--limit N` | Rows per section; default 200, `0` means no limit. |
| `--json` | Print JSON instead of text. |

A directory-qualified `--exe` also matches sessions whose target was selected by
name and has the same file name, because name-target sessions do not store a
path. Process, connection and DNS rows require the recorded image path to match.

### `export`

```
nettrace export --format csv|json [filters] [--out FILE] [--what TYPE]
```

`--what` accepts `all`, `sessions`, `processes`, `connections`, `dns`, and can be
repeated. With CSV and `--what all`, `--out` is a base name and NetTrace writes
`<base>.sessions.csv`, `<base>.processes.csv`, `<base>.connections.csv` and
`<base>.dns.csv`. Missing parent directories are created.

```powershell
.\nettrace.exe export --format csv --out .\out\connections.csv --what connections
.\nettrace.exe export --format json --out .\out\session-3.json --session 3
.\nettrace.exe export --format csv --exe "SC2_x64.exe" --proto tcp --port 443
```

CSV timestamps are UTC RFC3339. The sessions table contains `etw_enabled` and a
derived `etw_state` column (`no`, `yes (3/3 providers)` or
`partial (1/3 providers)`), so partial ETW coverage stays visible after export.

### `status`

```
nettrace status [--db PATH] [--json]
```

Reports the host, privilege level, database size/schema/row counts, whether each
ETW provider manifest is registered, and the last session's per-source health.
It does not start a capture. Exit code `1` means the database could not be read.

### `version`

```
.\nettrace.exe version
# NetTrace 0.1.0 (windows/amd64)
```

## Data locations

| Item | Default |
| --- | --- |
| Database | `%LOCALAPPDATA%\NetTrace\nettrace.db` |
| Config | `%LOCALAPPDATA%\NetTrace\config.json` |
| `NETTRACE_DB` environment variable | Overrides the database path. |
| `<command> --db PATH` | Highest priority. |

The config file only holds non-sensitive defaults:

```json
{
  "dbPath": "C:\\Users\\you\\AppData\\Local\\NetTrace\\nettrace.db",
  "pollIntervalMs": 2000,
  "localAddrRefreshSec": 30,
  "storeUnattributedDNS": false
}
```

SQLite runs in WAL mode with a 5s busy timeout, foreign keys enabled and
`synchronous=NORMAL`.

## Time handling

- All timestamps in SQLite are **UTC** in RFC3339-nanosecond text.
- The console and `history` render **local time with milliseconds**.
- ETW event timestamps come from the event header (`SystemTime`), not from the
  moment NetTrace processed them.
- Sampled rows use the polling instant. That is why sampled connections are
  labeled `observed` and `src=iphlpapi:poll`.

## Schema (version 1)

`schema_migrations` records applied versions. Migrations are forward-only; a
database created by a newer binary is rejected instead of being modified.

| Table | Purpose |
| --- | --- |
| `settings` | Database-level metadata (`db_created_utc`, `app_version`). |
| `monitor_sessions` | One row per `monitor` run: target, match kind, UTC start/end, status, capture note, `etw_enabled`, final source list, host/user/OS/app version. |
| `process_instances` | One row per observed execution: session, PID, parent PID, image name/path, start/detected/end, exit code, `already_running`, capture state, source. Unique on `(session_id, pid, started_utc)`. |
| `connection_events` | Aggregated TCP/UDP tuple and state: endpoints, protocol, IPv4/IPv6, state, event type, first/last seen, bytes sent/received, occurrences, source, detail. Unique `dedup_key`. |
| `dns_queries` | Aggregated completed DNS query: name, type, status, answers, attribution, first/last seen, occurrences, source, truncated raw blob. Unique `dedup_key`. |
| `source_status` | Final/health state per source and session (`running`, `degraded`, `error`, `unavailable`, `stopped`) with a human-readable detail. |

Aggregation is deliberate. Repeating identical data events does not create a row
per packet: the first/last timestamps, byte counters and `occurrences` are
updated instead. A state change produces a new row.

Dedup keys:

- Connections: `session|pid|proto|local_addr|local_port|remote_addr|remote_port|event_type|state`
- DNS: `session|pid|lower(query_name)|query_type`

## Sample records

The following comes from a real non-elevated test: a monitored PowerShell opened
a loopback TCP listener and client, sent one UDP datagram, and issued one DNS
query. Kernel ETW was denied, DNS-Client ETW worked.

Summary:

```text
Session #1 summary
  duration:    20.076s
  processes:   1 (started before capture: 0)
  connections: 4 sampled rows from IP Helper tables (short-lived connections may be missing)
  dns:         1 queries
  ETW:         partially active; active: DNS-Client; unavailable: Kernel-Network (Access is denied.), Kernel-Process (Access is denied.)
  storage:     63 written, 0 dropped, 0 failed
  completeness: limited (connections are sampled from IP Helper tables; short-lived connections can be missed)
```

`history` section:

```text
Sessions (1)
  #1  2026-10-26 02:42:59.670 -> 2026-10-26 02:43:19.745  powershell.exe  match=name  status=finished  etw=partial (1/3 providers)
       note: capture started before waiting for the target; activity before this instant is unknown;
             process token is not elevated; ETW was only partially available; active: DNS-Client;
             unavailable: Kernel-Network (Access is denied.), Kernel-Process (Access is denied.);
             IP Helper/Toolhelp32 sampling was used; short-lived connections can be missed

Processes (1)
  pid=21492 ppid=19796  session=#1  powershell.exe  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  start=2026-10-26 02:43:00.496 end=2026-10-26 02:43:09.650  captured_from_start  src=toolhelp:snapshot

Connections (4)
  2026-10-26 02:43:01.244  pid=21492  powershell.exe  tcp  127.0.0.1:9469 -> 0.0.0.0:0
      observed/listen  bytes=0/0 n=12  src=iphlpapi:poll  detail=sampled from IP Helper tables
  2026-10-26 02:43:01.244  pid=21492  powershell.exe  tcp  127.0.0.1:9469 -> 127.0.0.1:9470
      observed/established  bytes=0/0 n=12  src=iphlpapi:poll  detail=sampled from IP Helper tables
  2026-10-26 02:43:01.244  pid=21492  powershell.exe  tcp  127.0.0.1:9470 -> 127.0.0.1:9469
      observed/established  bytes=0/0 n=12  src=iphlpapi:poll  detail=sampled from IP Helper tables
  2026-10-26 02:43:01.244  pid=21492  powershell.exe  udp  0.0.0.0:58250 -> 0.0.0.0:0
      observed/bound  bytes=0/0 n=12  src=iphlpapi:poll  detail=sampled from IP Helper tables

DNS (1)
  2026-10-26 02:43:01.160  pid=21492  powershell.exe  xc11c864245984e69add5640adad047ad.example.com
      A  no_records  answers=-  n=1  attributed  src=etw:dns-client
```

CSV connection row (UTC):

```csv
1,1,1,21492,powershell.exe,tcp,4,127.0.0.1,9469,0.0.0.0,0,listen,observed,2026-10-26T06:43:01.2442Z,2026-10-26T06:43:08.9443Z,0,0,12,iphlpapi:poll,sampled from IP Helper tables
```

JSON session object:

```json
{
  "session_id": 1,
  "target_input": "powershell.exe",
  "target_name": "powershell.exe",
  "match_kind": "name",
  "started_utc": "2026-10-26T06:42:59.6702568Z",
  "ended_utc": "2026-10-26T06:43:19.7458285Z",
  "status": "finished",
  "etw_enabled": true,
  "etw_state": "partial (1/3 providers)",
  "sources": [
    "etw:dns-client=running",
    "etw:kernel-network=error",
    "etw:kernel-process=error",
    "iphlpapi:poll=running",
    "toolhelp:snapshot=running"
  ]
}
```

## Permissions and troubleshooting

**`ETW: partially active ... Access is denied.`**
Run the console as Administrator. Kernel ETW providers require an elevated token.
DNS-Client may still work in a standard console. This is reported, never hidden.

**No connections are recorded.**
Check that the target actually made a connection while capture was running. In
`--no-etw` mode the tables are sampled every `--poll-interval` (default 2s), so
connections shorter than the interval can be missed. Verify with
`Get-NetTCPConnection -OwningProcess <pid>` or `netstat -ano` while the process
runs. A TCP listener that only binds and never accepts still produces a
`listen` row.

**A process is missing or marked `already_running`.**
It was already running when capture started (or its start time was unavailable).
That is intentional: NetTrace never backfills earlier activity. Future children
and new instances are still captured.

**DNS rows are missing.**
DNS-Client ETW was unavailable, or the query was issued by a PID that is not a
monitored instance. Use `--dns-unattributed` to store unattributed rows, and run
elevated if ETW was denied. Cached answers may not generate a DNS-Client query.

**`database is locked`.**
Another NetTrace process is writing. SQLite allows concurrent readers; stop the
other `monitor`, or use a separate `--db` file. WAL files (`-wal`, `-shm`) are
normal.

**I need packet payloads or HTTPS URLs.**
Out of scope by design. NetTrace records endpoints and DNS metadata only; it does
not intercept TLS, decrypt traffic, or emulate HTTP.

## Tests

```powershell
cd .
gofmt -l .
go build ./...
go vet ./...
go test ./...
```

The test suite covers:

- Windows FILETIME conversion (including the zero-FILETIME overflow guard)
- IP Helper TCP/UDP table parsing with a live loopback listener
- Kernel-Network event mapping, endpoint orientation, IPv4/IPv6, failure codes
- DNS query/status/answer decoding and dedup keys
- Process instance lifecycle, `already_running`, PID reuse, exit codes
- SQLite schema, aggregation upserts, filters (`--exe`, path, domain wildcard
  escaping), writer draining
- CSV/JSON export, output directory creation, `etw_state`
- ETW summary/completeness/note accuracy for full, partial and disabled ETW
- Time parsing/formatting and target matching

Live verification performed in this workspace:

- Non-elevated DNS-Client ETW + sampled IP Helper/Toolhelp: recorded process
  start/end, TCP listen/established rows, a UDP bind row, and an attributed DNS
  query; correct partial-ETW reporting; 0 writer drops/failures.
- `--no-etw` loopback test: 3 aggregated TCP rows, correct process times.
- Elevated Kernel-Network/Kernel-Process capture has **not** been verified in
  this environment (the shell is not elevated). Run the monitor as Administrator
  and confirm `ETW: active (Kernel-Network, Kernel-Process, DNS-Client)` plus
  `connect`/`establish`/`data` rows and `captured_from_start` process events.

## Limitations and non-goals

- Observation only. No hosts file, DNS server, certificate store, proxy or
  firewall changes. No secrets are collected.
- No TLS interception, HTTP emulation, packet payload capture or GUI.
- ETW buffer loss is possible on a busy system; the loss counters are printed
  and stored in the capture note. Data events are intentionally aggregated, so
  per-packet timing is not preserved.
- The fallback cannot see short-lived connections between polls, process start
  from ETW (Toolhelp32 only), or DNS. Sampled rows have no byte counters.
- Connection history starts when capture starts. Earlier activity cannot be
  recovered.
- IPv4/IPv6 and TCP/UDP are covered. Other protocols, raw sockets, ICMP and
  localhost traffic that never appears in the IP Helper tables may be missing.
- DNS records only provide answers when the `QueryResults` blob can be decoded;
  otherwise the row keeps the name/type/status and a truncated raw hex string.
- The tool is not a security boundary. A malicious local process can forge or
  hide activity, and ETW itself is not tamper-proof.

## Project layout

```
nettrace/
  cmd/nettrace/          main entry point
  internal/cli/          monitor, history, export, status commands
  internal/collector/    ETW session, ingest, polling, source health
  internal/network/      Kernel-Network event mapping, endpoint orientation
  internal/dns/          DNS-Client mapping and QueryResults decoding
  internal/process/      process instance tracking and PID reuse
  internal/winproc/      Toolhelp32, IP Helper, FILETIME, identity helpers
  internal/storage/      SQLite schema, migrations, writer, statements
  internal/history/      filtered read queries
  internal/exporter/     CSV/JSON export
  internal/config/       config file and defaults
  internal/model/        shared data types
  docs/SOURCES.md        native source details and completeness rules
```
