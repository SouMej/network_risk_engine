def detect_bruteforce(store, attempt_threshold=4):
    alerts = []

    sensitive_ports = [22, 21, 3389, 8080]

    df = store.df[store.df["dst_port"].isin(sensitive_ports)]

    grouped = df.groupby(["src_ip", "dst_port"]).size()

    for (src, port), count in grouped.items():
        if count > attempt_threshold:
            alerts.append({
                "type": "BruteForce",
                "victim": src,
                "port": port,
                "attempts": count,
                "risk": 4
            })

    return alerts
