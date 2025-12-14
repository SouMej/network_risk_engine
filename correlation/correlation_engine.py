def correlate(all_results):
    correlation = {}

    for module_results in all_results:
        for r in module_results:

            # priorité des clés
            key = (
                r.get("attacker") or
                r.get("ip") or
                r.get("dns") or
                r.get("domain") or
                "unknown"
            )

            correlation.setdefault(key, 0)
            correlation[key] += r.get("risk", 0)

    return correlation
