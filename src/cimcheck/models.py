"""A subset of the Splunk CIM, expressed as validatable data models."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class DataModel:
    name: str
    required: List[str]
    recommended: List[str] = field(default_factory=list)
    types: Dict[str, str] = field(default_factory=dict)        # field -> "string|number|ip|bool"
    allowed: Dict[str, List[str]] = field(default_factory=dict)  # field -> allowed values


MODELS: Dict[str, DataModel] = {
    "Authentication": DataModel(
        name="Authentication",
        required=["action", "user", "src"],
        recommended=["dest", "app", "signature"],
        types={"action": "string", "user": "string", "src": "ip", "dest": "ip"},
        allowed={"action": ["success", "failure", "error"]},
    ),
    "Web": DataModel(
        name="Web",
        required=["action", "src", "dest", "http_method", "status"],
        recommended=["url", "http_user_agent", "bytes"],
        types={"status": "number", "bytes": "number", "src": "ip", "dest": "ip"},
        allowed={"http_method": ["GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS"]},
    ),
    "Network_Traffic": DataModel(
        name="Network_Traffic",
        required=["action", "src", "dest", "dest_port"],
        recommended=["transport", "bytes_in", "bytes_out"],
        types={"dest_port": "number", "src": "ip", "dest": "ip"},
        allowed={"action": ["allowed", "blocked", "teardown"],
                 "transport": ["tcp", "udp", "icmp"]},
    ),
    "Change": DataModel(
        name="Change",
        required=["action", "dvc", "object"],
        recommended=["command", "status", "user", "object_category"],
        types={"dvc": "string"},
        allowed={"action": ["created", "updated", "deleted", "read"],
                 "status": ["success", "failure"]},
    ),
}


def get_model(name: str) -> Optional[DataModel]:
    return MODELS.get(name)
