def analyze_dns(store):
    results = []

    dns_df = store.df[store.df["dns_query"].notna()]

    grouped = dns_df.groupby("dns_query").size()

    for domain, count in grouped.items():
        results.append({
            "dns_query": domain,
            "count": int(count),
            "risk": 1 if count > 10 else 0
        })

    return results
