# analyzers/port_analyzer.py
def analyze_ports(store):
    risky_ports = [4444, 6667, 1337]
    findings = []

    for _, row in store.df.iterrows():
        if row["dst_port"] in risky_ports:
            findings.append({
                "ip": row["dst_ip"],
                "port": row["dst_port"],
                "risk": 2
            })

    return findings
