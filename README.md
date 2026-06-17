# cimcheck — Splunk CIM compliance checker

[![CI](https://github.com/JCreatesGH/cim-check/actions/workflows/ci.yml/badge.svg)](https://github.com/JCreatesGH/cim-check/actions)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Validate that your events map cleanly to the Splunk **Common Information Model**. If a source isn't CIM-compliant, your data-model-driven dashboards and correlation searches silently return nothing — `cimcheck` catches that before it ships.

![screenshot](assets/screenshot.png)

## Install

```bash
pip install cimcheck
```

## Use it

```python
from cimcheck import get_model, check_event, check_events

model = get_model("Authentication")    # Web, Network_Traffic, Change also built in

for f in check_event(event, model):
    print(f.severity, f.rule, f.field, f.message)

report = check_events(events, model)
report.compliance_pct                  # 87.5
report.findings_by_rule                # {"missing-required": 3, "wrong-type": 1, ...}
```

## CLI

Installing the package adds a `cimcheck` command — feed it events as JSON (a list, or a Splunk
`{result:[...]}` export):

```bash
$ cimcheck Authentication events.json                  # compliance summary
$ cimcheck Web events.json --findings --json           # per-event findings, machine-readable
$ cimcheck Network_Traffic events.json --min-compliance 95   # exit 1 below 95% (CI gate)
$ cimcheck --list-models
```

## Checks

- **`missing-required`** (high) — a required CIM field is absent or empty; these break data-model acceleration.
- **`wrong-type`** (medium) — typed fields validated as `number` / `ip` (e.g. `status` must be numeric, `src`/`dest` must be IPs).
- **`invalid-value`** (medium) — enum fields checked against allowed sets (`action ∈ {success, failure, error}`, `http_method ∈ {GET, POST, …}`).
- **`missing-recommended`** (low) — recommended fields that improve correlation.

An event is counted "compliant" if it has no high-severity findings. Define your own `DataModel` to extend beyond the four built in (Authentication, Web, Network_Traffic, Change).

## Development

```bash
pip install -e .[dev] && python -m pytest -q   # 12 tests
```

## License

MIT
