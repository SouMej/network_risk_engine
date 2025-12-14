def analyze_behavior(store):
    results = []

    grouped = store.df.groupby("src_ip").size()

    for ip, count in grouped.items():
        if count > 1000:
            results.append({
                "ip": ip,
                "risk": 3,
                "reason": "High traffic burst"
            })

    return results
