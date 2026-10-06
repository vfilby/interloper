# Adapters

One directory per service the clearing house can guard. Each builds on the adapter core and shared command line in
[`../adapter`](../adapter), which also explains how adapters work and how to write a new one.

| Adapter | Guards | Binary | Status |
|---|---|---|---|
| [warpgate](warpgate/) | Warpgate SSH ticket requests | `interpose-adapter` | in use |
| [mailpit](mailpit/) | mail a Mailpit relay is holding (after an auto-release gate) | `interpose-adapter-mailpit` | new |

Planned (see docs/DESIGN.md, "Next adapters"): scoped document leases (Paperless via an MCP gateway).
