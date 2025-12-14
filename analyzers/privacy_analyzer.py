# analyzers/privacy_analyzer.py
def analyze_privacy(store):
    leaks = []

    for q in store.get_dns_queries():
        if "login" in q or "token" in q:
            leaks.append({
                "dns": q,
                "risk": 2
            })

    return leaks
