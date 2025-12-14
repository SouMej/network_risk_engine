def detect_dos(store, threshold=1000):

    alerts = []

    grouped = store.df.groupby(["src_ip", "dst_ip"]).size()

    for (src, dst), count in grouped.items():
        if count > threshold:
            alerts.append({
                "type": "DoS",
                "attacker": src,
                "victim": dst,
                "packets": count,
                "risk": 5
            })

    return alerts
