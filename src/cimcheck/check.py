"""Validate events against a CIM data model."""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List
from .models import DataModel

_IP = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+:[0-9a-fA-F:]+$")


@dataclass
class Finding:
    severity: str       # high | medium | low
    rule: str
    field: str
    message: str


def _type_ok(value: Any, type_: str) -> bool:
    if value is None or value == "":
        return False
    if type_ == "number":
        try:
            float(value); return True
        except (TypeError, ValueError):
            return False
    if type_ == "ip":
        return bool(_IP.match(str(value)))
    if type_ == "bool":
        return str(value).lower() in ("true", "false", "0", "1")
    return True   # string


def check_event(event: Dict[str, Any], model: DataModel) -> List[Finding]:
    out: List[Finding] = []
    for fname in model.required:
        if fname not in event or event[fname] in (None, ""):
            out.append(Finding("high", "missing-required", fname,
                f"Required CIM field '{fname}' is missing."))
    for fname, type_ in model.types.items():
        if fname in event and event[fname] not in (None, "") and not _type_ok(event[fname], type_):
            out.append(Finding("medium", "wrong-type", fname,
                f"Field '{fname}' should be {type_} (got {event[fname]!r})."))
    for fname, allowed in model.allowed.items():
        if fname in event and event[fname] not in (None, "") and str(event[fname]) not in allowed:
            out.append(Finding("medium", "invalid-value", fname,
                f"Field '{fname}'={event[fname]!r} not in allowed {allowed}."))
    for fname in model.recommended:
        if fname not in event:
            out.append(Finding("low", "missing-recommended", fname,
                f"Recommended CIM field '{fname}' is absent."))
    return out


@dataclass
class ComplianceReport:
    model: str
    total: int
    compliant: int
    findings_by_rule: Dict[str, int] = field(default_factory=dict)

    @property
    def compliance_pct(self) -> float:
        return round(100 * self.compliant / self.total, 1) if self.total else 100.0


def check_events(events: List[Dict[str, Any]], model: DataModel) -> ComplianceReport:
    compliant = 0
    by_rule: Dict[str, int] = {}
    for ev in events:
        findings = check_event(ev, model)
        if not any(f.severity == "high" for f in findings):
            compliant += 1
        for f in findings:
            by_rule[f.rule] = by_rule.get(f.rule, 0) + 1
    return ComplianceReport(model.name, len(events), compliant, by_rule)
