# Adapters

One directory per service the clearing house can guard. Each builds on the adapter core and shared command line in
[`../adapter`](../adapter), which also explains how adapters work and how to write a new one.

| Adapter | Guards | Binary | Status |
|---|---|---|---|
| [warpgate](warpgate/) | Warpgate SSH ticket requests | `wga-adapter` | in use |

Planned (see docs/DESIGN.md, "Next adapters"): held mail (Mailpit), scoped document leases (Paperless via an MCP
gateway).
