"""Command-line interface: check events against a Splunk CIM data model."""
from __future__ import annotations
import argparse
import json
import sys
from typing import List, Optional

from .models import MODELS, get_model
from .check import check_event, check_events


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cimcheck", description="Validate events against a Splunk CIM data model.")
    parser.add_argument("model", nargs="?", help=f"CIM model: {', '.join(MODELS)}")
    parser.add_argument("file", nargs="?", help="JSON: a list of events (or {result:[...]}); default stdin")
    parser.add_argument("--list-models", action="store_true", help="list the built-in data models and exit")
    parser.add_argument("--findings", action="store_true", help="show per-event findings, not just the summary")
    parser.add_argument("--min-compliance", type=float, default=None,
                        help="exit 1 if compliance %% is below this (CI gate)")
    parser.add_argument("--json", action="store_true", help="emit the report as JSON")
    args = parser.parse_args(argv)

    if args.list_models:
        for name, m in MODELS.items():
            print(f"{name}: required {m.required}")
        return 0

    model = get_model(args.model or "")
    if model is None:
        print(f"error: unknown model '{args.model}'; choose {list(MODELS)}", file=sys.stderr)
        return 2

    raw = open(args.file, encoding="utf-8").read() if args.file else sys.stdin.read()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"error: invalid JSON: {e}", file=sys.stderr)
        return 2
    events = data["result"] if isinstance(data, dict) and "result" in data else data
    if not isinstance(events, list):
        print("error: expected a JSON list of events (or {result: [...]})", file=sys.stderr)
        return 2

    report = check_events(events, model)

    if args.json:
        out = {"model": report.model, "total": report.total, "compliant": report.compliant,
               "compliance_pct": report.compliance_pct, "findings_by_rule": report.findings_by_rule}
        if args.findings:
            out["events"] = [[f.__dict__ for f in check_event(ev, model)] for ev in events]
        print(json.dumps(out, indent=2))
    else:
        print(f"CIM {report.model} compliance: {report.compliance_pct}%  "
              f"({report.compliant}/{report.total} events)")
        for rule, n in sorted(report.findings_by_rule.items(), key=lambda kv: -kv[1]):
            print(f"  {rule}: {n}")
        if args.findings:
            for i, ev in enumerate(events):
                for f in check_event(ev, model):
                    print(f"  event[{i}] {f.severity.upper()} {f.rule} {f.field}: {f.message}")

    if args.min_compliance is not None and report.compliance_pct < args.min_compliance:
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
