
import re

def detect_dns_tunneling(store):
    alerts = []

    for q in store.get_dns_queries():
        score = 0

        if len(q) > 50:
            score += 2

        if q.count('.') > 5:
            score += 2

        if re.search(r"[0-9]{6,}", q):
            score += 1

        if score >= 3:
            alerts.append({
                "type": "DNS Tunneling",
                "domain": q,
                "risk": score
            })

    return alerts
