def compute_priority(v):
    return (
        v["severity"] * 0.4 +
        v["epss"] * 0.3 +
        v["asset_criticality"] * 0.2 -
        (0.1 if v.get("duplicate", False) else 0)
    )
