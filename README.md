# dbfw-agent-core

Shared Go library for the [DB-Firewall](https://github.com/DB-Firewall) agents.
Pure standard library, no external dependencies.

Packages:
- `engine` — deterministic rule engine (allow/alert/block/ignore) + default rule sets, and the `EventSink`/`QueryMeta` contract.
- `protocol/{postgres,mysql,mongodb}` — wire-protocol packet framing and SQL/command extraction (incl. prepared-statement reconstruction for Postgres).
- `console` — HTTP client that ships events/heartbeats to `dbfw-console`.
- `backend` — backend DB dialer.
- `tlsutil` — self-signed cert helpers for TLS termination.

Consumed by `dbfw-proxy-agent` (inline) and `dbfw-tap-agent` (passive).

```go
import "github.com/DB-Firewall/dbfw-agent-core/engine"
```
