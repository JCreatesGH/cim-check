"""cimcheck: validate events against a Splunk Common Information Model data model."""
from .models import DataModel, MODELS, get_model
from .check import check_event, check_events, Finding, ComplianceReport
__all__ = ["DataModel", "MODELS", "get_model", "check_event", "check_events",
           "Finding", "ComplianceReport"]
__version__ = "0.1.0"
