# Changelog

All notable changes to this project are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [0.2.0]

### Added
- **Field-alias detection.** When a required/recommended CIM field is missing but a common
  alternate name holds the value (`username` → `user`, `src_ip` → `src`, `response_code` →
  `status`, …), cimcheck now reports a `field-aliased` finding instead of a bare
  `missing-required`, carrying the exact `FIELDALIAS` line that fixes it.
- **props.conf remediation.** `suggest_fieldaliases(events, model)` votes across the whole
  dataset to pick the most likely source field per CIM field, and `render_props_conf(st, …)`
  emits a paste-ready Splunk stanza. New CLI flag `--fieldalias <sourcetype>`.
- The human summary now lists fixable aliases; `--json` output gains a `suggested_aliases` map.
- Each built-in model (Authentication, Web, Network_Traffic, Change) ships a curated
  `aliases` map of real-world field names; `DataModel` gained an `aliases` field.

### Changed
- `missing-required` / `missing-recommended` now fire only when *no* alias is detected — an
  aliasable field is reported as the more actionable `field-aliased` instead.

## [0.1.0]

- Initial release: validate events against four built-in Splunk CIM data models with
  `missing-required`, `wrong-type`, `invalid-value`, and `missing-recommended` checks, a
  compliance report, and a CLI with a `--min-compliance` CI gate.
