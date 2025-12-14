from extractor.pcap_reader import load_pcap
from extractor.event_extractor import extract_events
from store.observable_store import ObservableStore
from analyzers.dos_analyzer import detect_dos
from analyzers.portscan_analyzer import detect_port_scan
from analyzers.dns_tunnel_analyzer import detect_dns_tunneling
from analyzers.bruteforce_analyzer import detect_bruteforce
from analyzers.http_exfiltration_analyzer import detect_http_exfiltration

from correlation.correlation_engine import correlate

from analyzers import (
    ip_analyzer, dns_analyzer,
    port_analyzer, behavior_analyzer, privacy_analyzer
)

from correlation.correlation_engine import correlate
from scoring.risk_score import compute_global_score
from output.exporter import export_csv, export_json

packets = load_pcap(r"C:\Users\sonia\py\network-risk-engine\pcap\viepriv.pcap")
df = extract_events(packets)
store = ObservableStore(df)

results = [
    ip_analyzer.analyze_ips(store),
    dns_analyzer.analyze_dns(store),
    port_analyzer.analyze_ports(store),
    behavior_analyzer.analyze_behavior(store),
    privacy_analyzer.analyze_privacy(store),
    detect_dos(store),
    detect_port_scan(store),
    detect_dns_tunneling(store),
    detect_bruteforce(store),
    detect_http_exfiltration(store) 
]



correlation = correlate(results)
score = compute_global_score(correlation)

print("Global Risk Score:", score)

export_csv(correlation, r"C:\Users\sonia\py\network-risk-engine\output\report.csv")
export_json(correlation, r"C:\Users\sonia\py\network-risk-engine\output\report.json")


for alert in results:
    for a in alert:
        print(a)

dns_results = dns_analyzer.analyze_dns(store)

print("==== DNS QUERIES ====")
for r in dns_results:
    print(f"{r['dns_query']}  →  {r['count']} times")
