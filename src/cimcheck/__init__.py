"""cimcheck: validate events against a Splunk Common Information Model data model."""
from .models import DataModel, MODELS, get_model
from .check import (
    check_event, check_events, find_alias, suggest_fieldaliases, render_props_conf,
    Finding, ComplianceReport,
)
__all__ = ["DataModel", "MODELS", "get_model", "check_event", "check_events",
           "find_alias", "suggest_fieldaliases", "render_props_conf",
           "Finding", "ComplianceReport"]
__version__ = "0.2.0"
