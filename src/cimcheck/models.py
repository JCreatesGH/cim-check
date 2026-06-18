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
    aliases: Dict[str, List[str]] = field(default_factory=dict)  # CIM field -> likely source names


MODELS: Dict[str, DataModel] = {
    "Authentication": DataModel(
        name="Authentication",
        required=["action", "user", "src"],
        recommended=["dest", "app", "signature"],
        types={"action": "string", "user": "string", "src": "ip", "dest": "ip"},
        allowed={"action": ["success", "failure", "error"]},
        aliases={
            "action": ["result", "outcome", "auth_action"],
            "user": ["username", "user_name", "account", "userid", "user_id", "samaccountname"],
            "src": ["src_ip", "srcip", "source_ip", "src_host", "client_ip", "clientip"],
            "dest": ["dest_ip", "destip", "dst", "dst_ip", "destination_ip", "dest_host"],
            "app": ["application", "service"],
        },
    ),
    "Web": DataModel(
        name="Web",
        required=["action", "src", "dest", "http_method", "status"],
        recommended=["url", "http_user_agent", "bytes"],
        types={"status": "number", "bytes": "number", "src": "ip", "dest": "ip"},
        allowed={"http_method": ["GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS"]},
        aliases={
            "src": ["src_ip", "srcip", "client_ip", "c_ip", "clientip"],
            "dest": ["dest_ip", "dst", "s_ip", "server_ip"],
            "http_method": ["method", "cs_method", "request_method", "verb"],
            "status": ["status_code", "response_code", "responsecode", "sc_status", "http_status"],
            "url": ["uri", "cs_uri_stem", "request_url", "uri_path"],
            "http_user_agent": ["user_agent", "useragent", "cs_user_agent", "ua"],
            "bytes": ["size", "length", "content_length"],
        },
    ),
    "Network_Traffic": DataModel(
        name="Network_Traffic",
        required=["action", "src", "dest", "dest_port"],
        recommended=["transport", "bytes_in", "bytes_out"],
        types={"dest_port": "number", "src": "ip", "dest": "ip"},
        allowed={"action": ["allowed", "blocked", "teardown"],
                 "transport": ["tcp", "udp", "icmp"]},
        aliases={
            "src": ["src_ip", "srcip", "source_ip", "source_address"],
            "dest": ["dest_ip", "destip", "dst", "destination_ip", "destination_address"],
            "dest_port": ["dport", "dst_port", "destination_port", "port"],
            "transport": ["proto", "protocol", "ip_protocol"],
            "bytes_in": ["in_bytes", "bytes_received", "rx_bytes"],
            "bytes_out": ["out_bytes", "bytes_sent", "tx_bytes"],
        },
    ),
    "Change": DataModel(
        name="Change",
        required=["action", "dvc", "object"],
        recommended=["command", "status", "user", "object_category"],
        types={"dvc": "string"},
        allowed={"action": ["created", "updated", "deleted", "read"],
                 "status": ["success", "failure"]},
        aliases={
            "dvc": ["device", "dvc_host", "host"],
            "object": ["obj", "target", "object_name", "resource"],
            "user": ["username", "user_name", "account"],
            "command": ["cmd", "command_line"],
            "object_category": ["obj_category", "category"],
        },
    ),
}


def get_model(name: str) -> Optional[DataModel]:
    return MODELS.get(name)
