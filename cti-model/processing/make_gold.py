import pandas as pd
from config import CRITICALITY_WEIGHT, KEV_MULTIPLIER


def make_gold_table(silver):
    silver["composite_score"] = (
        silver["cvss_score"].fillna(1)
        * silver["in_kev"].astype(int).map(KEV_MULTIPLIER)
        * silver["gi_criticality"].map(CRITICALITY_WEIGHT)
    ).round(3)

    gold_attributes = (
        silver[["cve_id", "date_published", "cve_description", "gi_software_name", "gi_vendor", "cvss_score", "in_kev", "composite_score"]]
        .drop_duplicates(subset=["cve_id", "gi_software_name"])
        .reset_index(drop=True)
    )

    return gold_attributes
