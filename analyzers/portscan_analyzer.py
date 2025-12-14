def detect_port_scan(store, port_threshold=20):
    alerts = []

    grouped = store.df.groupby("src_ip")["dst_port"].nunique()

    for ip, unique_ports in grouped.items():
        if unique_ports > port_threshold:
            alerts.append({
                "type": "PortScan",
                "attacker": ip,
                "ports_scanned": unique_ports,
                "risk": 4
            })

    return alerts
