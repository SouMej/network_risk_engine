import ipaddress
import requests
def get_geo(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            return None
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = r.json()

        if data["status"] == "success":
            return {
                "country": data["country"],
                "city": data["city"],
                "isp": data["isp"]
            }
    except:
        pass
    return None
def analyze_ips(store):
    alerts = []
    for ip in store.get_ips():
        score = 0
        reasons = []
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_loopback:
                reasons.append("Loopback address")
                score += 0  # not suspicious
            elif ip_obj.is_private:
                reasons.append("Private network IP")
                score += 0
            else:
                reasons.append("Public IP observed")
                score += 1
        except ValueError:
            reasons.append("Invalid IP format")
            score += 2
        geo = get_geo(ip)
        if geo:
            reasons.append(f"Geo: {geo['country']} / {geo['isp']}")
            score += 1
        alerts.append({
            "ip": ip,
            "risk": score,
            "reasons": reasons
        })
    return alerts

