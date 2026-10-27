# NetTrace event sources

This document explains where each record comes from, why the source was chosen,
what it can and cannot see, and how failures are reported. It complements
[../README.md](../README.md).

## Design constraints

- Observation only: no drivers, no hosts/DNS/certificate changes, no TLS
  interception, no packet payload capture.
- No mandatory Npcap installation or capture service.
- Capture must start before waiting for the target process.
- Never claim activity that happened before capture started.
- Never claim a source is active when it failed; partial availability must be
  visible in the console, the database and exported JSON/CSV.

For those reasons NetTrace uses documented Windows ETW providers as the primary
source and documented user-mode APIs as a fallback.

## ETW session lifecycle

- A private real-time session named `NetTrace-<pid>-<unix-nanoseconds>` is
  created per `monitor` run.
- Providers are enabled **before** the first process snapshot and before waiting
  for the target.
- `github.com/0xrawsec/golang-etw` provides the real-time session, consumer and
  TDH event decoding.
- Provider enablement is tracked independently. `startETWRuntime` returns an
  error only when **all three** providers fail. If one or two fail, the session
  runs with the rest and records each failure in `source_status` with the Win32
  error text (for example `Access is denied.`).
- `monitor_sessions.etw_enabled` means "ETW was requested and at least one
  provider ran". It does **not** mean full coverage; `sources_json`,
  `source_status`, the derived `etw_state` and the capture note carry the
  per-provider truth.
- Every 15 seconds a health loop checks that the session still exists. It
  refreshes **only providers that were successfully enabled**. A live session
  must never overwrite an individual provider's startup error.
- On stop, the consumer is stopped, queued events are drained, the session is
  stopped, and ETW's `LostEvents` counter plus NetTrace's own queue-drop counter
  are preserved for the final summary.

## Primary providers

| Provider | GUID | Enable level | Match any keyword |
| --- | --- | --- | --- |
| `Microsoft-Windows-Kernel-Network` | `{7dd42a49-5329-4832-8dfd-43d979153a88}` | `0xff` | `0` |
| `Microsoft-Windows-Kernel-Process` | `{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}` | `0xff` | `0x10` |
| `Microsoft-Windows-DNS-Client` | `{1c95126e-7eea-49a9-a3fe-a378b03ddb4d}` | `0xff` | `0x8000000000000000` |

Providers are resolved by name through ETW; if a manifest is not registered the
provider is reported as unavailable and the session continues with the rest.
`status` checks manifest registration independently of a capture.

### `Microsoft-Windows-Kernel-Network`

NetTrace consumes these event IDs (fields are decoded by TDH):

| IDs | Protocol | Event type | State |
| --- | --- | --- | --- |
| 10 / 11 | TCP IPv4 | `data` | (none), outbound / inbound |
| 12 | TCP IPv4 | `connect` | `syn_sent` |
| 13 | TCP IPv4 | `close` | `closed` |
| 14 | TCP IPv4 | `retransmit` | (none) |
| 15 | TCP IPv4 | `establish` | `established` |
| 16 | TCP IPv4 | `reconnect` | `reconnecting` |
| 17 | TCP IPv4 | `fail` | `failed` |
| 18 | TCP IPv4 | `copy` | (none) |
| 26 / 27 | TCP IPv6 | `data` | (none), outbound / inbound |
| 28–34 | TCP IPv6 | `connect`, `close`, `retransmit`, `establish`, `reconnect`, `fail`, `copy` | as above |
| 42 / 43 | UDP IPv4 | `datagram` | outbound / inbound |
| 49 | UDP IPv4 | `fail` | `failed` |
| 58 / 59 | UDP IPv6 | `datagram` | outbound / inbound |

Relevant fields: `PID`, `saddr`, `daddr`, `sport`, `dport`, `size`,
`connid`, `FailureCode` (some builds expose the failure code as `size`).
A `PID` field is preferred; otherwise the event header process ID is used.
PID 0 events are ignored.

Endpoint orientation:

- Kernel-Network swaps `saddr`/`daddr` depending on direction, so orientation
  cannot rely on the field names alone.
- NetTrace caches the host's local addresses (`LocalAddresses`, TTL 30s by
  default) and treats the local side as local. If both sides are local (loopback)
  or unknown, the event direction decides.
- IPv4 addresses may arrive as dotted strings or as decimal little-endian
  DWORDs; both are accepted. IPv6 may arrive as text or as 32 hex digits.
- The resolver keeps its last good address set if a refresh fails, so a transient
  adapter error does not silently corrupt orientation.

Only the connection tuple, state, event type, byte count and a detail string are
stored. Payload bytes are never captured.

### `Microsoft-Windows-Kernel-Process`

| Event ID | Meaning | Fields used |
| --- | --- | --- |
| 1 | Process start | `ProcessID`, `ParentProcessID`, `ImageName` |
| 2 | Process stop | `ProcessID`, `ExitCode` |

For a start event NetTrace resolves the image path and creation time through
process APIs. If the event's image path is unavailable, the `ImageName` device
path is converted to a DOS path. The target match is then evaluated by image name
or full path. Process stop events close the instance and record the exit code
when present.

Toolhelp32 polling still runs alongside ETW. It is the only start/stop source when
Kernel-Process is denied, and it also catches instances ETW may miss or reports
duplicates already handled by the process manager.

### `Microsoft-Windows-DNS-Client`

NetTrace requests events 3006 (`query called`) and 3008 (`query completed`) but
stores only 3008. Event 3006 has no answers and would duplicate the completed row.

| Field | Use |
| --- | --- |
| `QueryName` | Trimmed, trailing dot removed, max 255 chars. |
| `QueryType` | Numeric type; mapped to `A`, `AAAA`, `CNAME`, `HTTPS`, ... |
| `QueryStatus` | Numeric status; mapped to `success`, `name_not_found`, `timeout`, ... |
| `QueryResults` | Binary blob, decoded on a best-effort basis. |

Attribution:

- The event header process ID is the process that called the DNS API
  (`dnsapi.dll` emits in the caller's context).
- A query is stored only when that PID currently resolves to a **monitored
  process instance**; the instance ID and executable name are attached and
  `attributed=1`, `attribution=etw_process_id`.
- With `--dns-unattributed`, queries from other PIDs are stored with
  `attributed=0`, `attribution=unattributed`. They are never assigned to a
  monitored process.
- No DNS source is installed or proxied. The system resolver remains untouched.

`QueryResults` decoding:

1. The TDH `win:Binary` representation is normally a hex string.
2. A complete DNS response message is parsed first (header, questions, answer
   names with compression pointers). A, AAAA and CNAME answers are extracted.
3. A bare answer-record sequence is attempted second.
4. If decoding fails, the name/type/status are still stored and the raw hex is
   kept, truncated to 2048 hex characters.

Because answers depend on what the provider supplies, an NXDOMAIN or NODATA
response may legitimately have zero answers. The row still records the status.

## Fallback sources (no ETW)

When `--no-etw` is used, or when every ETW provider is denied:

| Source | API | Interval | Data |
| --- | --- | --- | --- |
| `iphlpapi:poll` | `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)` and `GetExtendedUdpTable(UDP_TABLE_OWNER_PID)` | `--poll-interval`, default 2s, minimum 250ms | Current TCP/UDP tuples, state and owning PID for IPv4/IPv6 |
| `toolhelp:snapshot` | `CreateToolhelp32Snapshot`/`Process32First/Next` | same interval | Process ID, parent ID, image name/path, creation time |

The fallback rows are explicitly labeled:

- `event_type=observed`
- `source=iphlpapi:poll`
- `detail=sampled from IP Helper tables`
- no byte counters, because the tables do not expose them
- `listen` rows use remote `0.0.0.0:0` / `[::]:0`

Consequences of sampling:

- Connections shorter than the polling interval may never appear.
- A connection that changes state between polls can hide intermediate states.
- One-shot UDP sockets may be gone before the first poll.
- DNS is not collected at all; DNS-Client is an ETW provider.
- Process starts can be detected up to one interval late; process start time
  still comes from the process creation time when available.

Polling is enabled automatically if Kernel-Network could not be enabled, even
when DNS-Client ETW is active. This is why a session can be "partial" and still
contain sampled connection rows plus attributed DNS rows.

## Process identity and capture state

- The target is matched by image name (case-insensitive, all instances) or by
  full path (must exist when `monitor` starts).
- Toolhelp32 and ETW observations are deduplicated by PID plus creation time.
- A PID that is reused with a different creation time closes the old instance
  and starts a new one.
- `already_running=1` and `capture_state=already_running` are used when the
  process started before the session start (with 1 second of slack) or was
  present in the initial snapshot without a known start time.
- Recently ended instances stay resolvable for 30 seconds, so trailing close or
  data events are still attached to the correct instance rather than dropped.
- Exit codes are recorded when the source provides them (ETW event 2); Toolhelp32
  and sampled fallback may leave them unknown.

## Storage and loss accounting

- One writer goroutine owns all writes. Event producers never block on SQLite.
- Queue capacity is 8192 records; records are flushed in batches of up to 128
  every 200ms, or immediately when the batch is full.
- A full queue drops the record and increments a counter; the final summary
  reports drops. ETW's own `LostEvents` counter is reported separately.
- Inserts are upserts on a dedup key. Identical events update first/last seen,
  byte counters and occurrence count; state changes create new rows.
- If a batch transaction fails, records are retried one by one because the
  upserts are idempotent.
- `source_status` rows are written only when a source's state or detail changes,
  so a long poll loop does not flood the database.
- WAL, foreign keys and `synchronous=NORMAL` are enabled. All timestamps are UTC.

## Completeness reporting

`monitor` prints one of these completeness lines, derived from the final source
states rather than from a single global flag:

- Full ETW: `limited to events observed after capture started; ETW buffer loss is possible`
- Kernel-Network denied: `limited (connections are sampled from IP Helper tables; short-lived connections can be missed)`
- Network and DNS missing: `limited (network and DNS are sampled or missing; short-lived connections can be missed)`
- ETW disabled: `limited (sampled sources; short-lived connections can be missed; DNS is not collected)`

The capture note stored with the session contains the per-provider outcome and
any loss/drop counts. `history`, `status` and exported data expose the same
information, including `etw_state`.

## Why not WFP, a driver or Npcap?

- **WFP** can observe connections and could provide richer metadata, but a
  transparent, always-on WFP callout requires a kernel driver and careful
  security review. That is disproportionate for an observation-only console
  tool.
- **Npcap** would provide packets, but the requirement explicitly makes it
  optional, and packet capture still needs a driver and a capture service.
- **`netstat` parsing** is fragile (localized output, timing, no stable schema)
  and cannot provide process start events or DNS attribution.
- **ETW** is documented, built into Windows, needs no install, provides process,
  TCP/UDP and DNS events with timestamps and PIDs, and degrades cleanly when a
  provider is denied.

The data model (`model.RawEvent` plus provider mappers) is source-neutral. A
future packet or WFP source can be added without changing storage or history.

## Verification status

Verified in this workspace:

- Non-elevated run: DNS-Client ETW active; Kernel-Network and Kernel-Process
  denied with `Access is denied.`; automatic IP Helper/Toolhelp fallback;
  correct partial `etw_state`; attributed DNS query; TCP listen/established and
  UDP bind rows; 0 writer drops/failures.
- `--no-etw` run: loopback listener/client produced listen and both established
  directions, correct process start/end and `captured_from_start`.
- Unit tests cover FILETIME conversion, IP Helper parsing, event mapping,
  endpoint orientation, DNS decoding, process lifecycle/PID reuse, schema
  upserts, filters, export and ETW reporting.

Not yet verified here:

- An **elevated** session with Kernel-Network and Kernel-Process actually
  enabled. The current shell is not elevated. Validate manually with an
  Administrator console:

  ```powershell
  .\nettrace.exe monitor --name notepad.exe --duration 20s
  # expect: ETW: active (Kernel-Network, Kernel-Process, DNS-Client)
  # then start notepad.exe, open a TCP connection, run Resolve-DnsName
  ```

## Known gaps

- No packet payload, TLS decryption, HTTP request reconstruction or certificate
  inspection.
- No recovery of activity before capture started.
- ETW data events are aggregated; per-packet order and exact wire timing are not
  retained.
- Loss is detected and reported but cannot be eliminated; a busy host can still
  lose ETW events.
- DNS answers depend on the provider's blob; not every Windows build emits the
  same shape, and the raw hex is truncated.
- Some traffic (ICMP, raw sockets, traffic not owned by a monitored PID, or rows
  that disappear between samples) may be absent.
- The tool trusts local PIDs and ETW. It is not a tamper-proof security control.
