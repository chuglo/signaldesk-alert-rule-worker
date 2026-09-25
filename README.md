# SignalDesk alert rule worker

**Not for production use.**

Consumes fenced `diagnostic.terminal.v2` events, rechecks the authoritative
control-plane diagnostic, resolves the tenant-scoped monitor rule, and creates
an idempotent diagnostic alert notification. Redis contains identifiers only;
diagnostic results and recipient data remain in their owning services.

Run one bounded iteration with `signaldesk-alert-rule-worker --once`, or use
`--ready` for dependency readiness. Configuration uses the `SIGNALDESK_`
environment prefix.

## License

MIT. See [LICENSE](LICENSE).
