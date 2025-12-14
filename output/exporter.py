# output/exporter.py
import json
import pandas as pd

def export_csv(correlation, path):
    df = pd.DataFrame([
        {"entity": k, "risk": v} for k, v in correlation.items()
    ])
    df.to_csv(path, index=False)

def export_json(correlation, path):
    with open(path, "w") as f:
        json.dump(correlation, f, indent=2)
