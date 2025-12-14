# scoring/risk_score.py
def compute_global_score(correlation):
    total = sum(correlation.values())
    max_score = len(correlation) * 5
    return round((total / max_score) * 100, 2) if max_score else 0
