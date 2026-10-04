# Contributing

- Run the tests before opening a PR: `python -m unittest discover -s tests -t . -v`.
- Standard library plus Flask only. Avoid new dependencies.
- New known-device sources go in `sources/` and need a test using a mock server or a temp file.
- Device names, vendors and labels come from the air and are attacker-controlled. The
  dashboard renders them with `textContent` only; keep it that way.
- Say what you verified on real hardware (Kismet version, adapter, UniFi version). Unverified
  field names are the project's biggest risk, so reports are as valuable as code.
- Keep detection changes conservative: a false alarm every night gets the system turned off.
