import pandas as pd
import json
import re

# Load Excel
df = pd.read_excel("ici.xlsx")

# Create base MITRE Navigator layer
layer = {
    "version": "4.5",
    "name": "ICICI Threat Mapping",
    "description": "Mapped threats and detections from ICICI context",
    "domain": "enterprise-attack",
    "techniques": [],
    "gradient": {
        "colors": ["#ffffff", "#ff6666"],  # white to red
        "minValue": 0,
        "maxValue": 1
    },
    "legendItems": [],
    "metadata": [],
    "filters": {
        "platforms": ["Windows", "Linux", "macOS"]
    },
    "layout": {
        "layout": "side",
        "showName": True,
        "showID": False,
        "showAggregateScores": False,
        "countUnscored": False
    }
}

# Loop through rows
for _, row in df.iterrows():
    tactic = str(row["MITRE Tactic"]).strip().lower().replace(" ", "-")
    
    # Extract technique or subtechnique ID
    full_tech = str(row["MITRE Technique / Sub-tech"])
    match = re.match(r"(T\d+\.\d+|T\d+)", full_tech)
    if not match:
        continue
    tech_id = match.group(1)

    # Comment: combine threat scenario + detection logic + severity
    comment_parts = []
    for col in ["Threat Scenario (ICICI Banking Context)", "Detection Logic (high level)", "Severity"]:
        if pd.notna(row[col]):
            comment_parts.append(str(row[col]))
    comment = " | ".join(comment_parts)

    # Determine if it's a subtechnique
    is_subtech = "." in tech_id

    technique_entry = {
        "techniqueID": tech_id,
        "tactic": tactic,
        "color": "#ff6666",  # red
        "comment": comment,
        "enabled": True,
        "metadata": [],
        "showSubtechniques": False,
        "score": 1
    }

    layer["techniques"].append(technique_entry)

# Save output JSON
with open("icici_layer.json", "w") as f:
    json.dump(layer, f, indent=4)

print("Layer created: icici_layer.json")# trigger workflow
# Trigger workflow run