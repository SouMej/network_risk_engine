from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from scapy.layers.dns import DNS
import pandas as pd

def detect_http_exfiltration(store, byte_threshold=2000):
    alerts = []

    required = {"protocol", "dst_port", "payload_size", "method"}
    if not required.issubset(store.df.columns):
        return alerts

    df = store.df[
        (store.df["protocol"] == "TCP") &
        (store.df["dst_port"].isin([80, 8080]) &
        (store.df["src_ip"] != store.df["dst_ip"]))
    ]

    grouped = df.groupby(["src_ip", "dst_ip"])

    for (src, dst), group in grouped:
        total_bytes = group["payload_size"].sum()
        post_count = (group["method"] == "POST").sum()

        if total_bytes > byte_threshold or post_count > 30:
            alerts.append({
                "type": "HTTP Exfiltration",
                "attacker": dst,
                "victim": src,
                "bytes_sent": int(total_bytes),
                "post_requests": int(post_count),
                "risk": 5
            })

    return alerts
