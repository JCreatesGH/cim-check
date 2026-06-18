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


def _present(event: Dict[str, Any], fname: str) -> bool:
    return fname in event and event[fname] not in (None, "")


def find_alias(event: Dict[str, Any], model: DataModel, cim_field: str) -> str | None:
    """If `cim_field` is absent but a known source-name alias holds a value, return it."""
    for alt in model.aliases.get(cim_field, []):
        if _present(event, alt):
            return alt
    return None


def check_event(event: Dict[str, Any], model: DataModel) -> List[Finding]:
    out: List[Finding] = []
    for fname in model.required:
        if not _present(event, fname):
            alias = find_alias(event, model, fname)
            if alias:
                out.append(Finding("high", "field-aliased", fname,
                    f"Required CIM field '{fname}' is missing, but '{alias}' looks like it — "
                    f"add `FIELDALIAS-cim_{fname} = {alias} AS {fname}`."))
            else:
                out.append(Finding("high", "missing-required", fname,
                    f"Required CIM field '{fname}' is missing."))
    for fname, type_ in model.types.items():
        if _present(event, fname) and not _type_ok(event[fname], type_):
            out.append(Finding("medium", "wrong-type", fname,
                f"Field '{fname}' should be {type_} (got {event[fname]!r})."))
    for fname, allowed in model.allowed.items():
        if _present(event, fname) and str(event[fname]) not in allowed:
            out.append(Finding("medium", "invalid-value", fname,
                f"Field '{fname}'={event[fname]!r} not in allowed {allowed}."))
    for fname in model.recommended:
        if not _present(event, fname):
            alias = find_alias(event, model, fname)
            if alias:
                out.append(Finding("low", "field-aliased", fname,
                    f"Recommended CIM field '{fname}' is missing, but '{alias}' looks like it — "
                    f"add `FIELDALIAS-cim_{fname} = {alias} AS {fname}`."))
            else:
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


def suggest_fieldaliases(events: List[Dict[str, Any]], model: DataModel) -> Dict[str, str]:
    """Across all events, map each missing CIM field to its most common detected alias.

    This is the remediation cimcheck recommends: the source field that *should* be
    aliased to the CIM name. Returns ``{cim_field: source_field}`` ordered by CIM field.
    """
    votes: Dict[str, Dict[str, int]] = {}
    for ev in events:
        for cim_field in (*model.required, *model.recommended):
            if _present(ev, cim_field):
                continue
            alias = find_alias(ev, model, cim_field)
            if alias:
                votes.setdefault(cim_field, {})[alias] = votes.setdefault(cim_field, {}).get(alias, 0) + 1
    # winner per field: highest count, ties broken by alias name for determinism
    return {
        cf: sorted(tally.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
        for cf, tally in votes.items()
    }


def render_props_conf(sourcetype: str, aliases: Dict[str, str]) -> str:
    """Render a Splunk ``props.conf`` stanza of FIELDALIAS lines for the detected aliases."""
    lines = [f"[{sourcetype}]"]
    if not aliases:
        lines.append("# No field aliases needed — events already use CIM field names.")
    for cim_field, source in sorted(aliases.items()):
        lines.append(f"FIELDALIAS-cim_{cim_field} = {source} AS {cim_field}")
    return "\n".join(lines) + "\n"
