from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from scapy.layers.dns import DNS
import pandas as pd

def extract_events(packets):
    events = []

    for pkt in packets:
        if IP not in pkt:
            continue

        event = {
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
            "src_port": None,
            "dst_port": None,
            "protocol": None,
            "payload_size": 0,
            "dns_query": None,
            "method": None  # Pour HTTP si possible
        }

        if TCP in pkt:
            event["protocol"] = "TCP"
            event["src_port"] = pkt[TCP].sport
            event["dst_port"] = pkt[TCP].dport

            if Raw in pkt:
                event["payload_size"] = len(pkt[Raw].load)
                # Détecter POST/GET si texte clair
                payload_str = pkt[Raw].load.decode(errors="ignore")
                if payload_str.startswith("POST"):
                    event["method"] = "POST"
                elif payload_str.startswith("GET"):
                    event["method"] = "GET"

        elif UDP in pkt:
            event["protocol"] = "UDP"
            event["src_port"] = pkt[UDP].sport
            event["dst_port"] = pkt[UDP].dport

        if DNS in pkt and pkt[DNS].qd:
            event["dns_query"] = pkt[DNS].qd.qname.decode()

        events.append(event)

    return pd.DataFrame(events)