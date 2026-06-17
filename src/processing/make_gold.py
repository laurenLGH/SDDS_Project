import sys
import sqlite3
import pandas as pd
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))
from config import DB_PATH, CRITICALITY_WEIGHT as criticality_weight, KEV_MULTIPLIER


def make_gold_table(silver):
    silver["composite_score"] = (
        silver["cvss_score"].fillna(1)
        * silver["in_kev"].astype(int).map(KEV_MULTIPLIER)
        * silver["gi_criticality"].map(criticality_weight)
    ).round(3)

    gold_attributes = (
        silver[["cve_id", "date_published", "cve_description", "gi_software_name", "gi_vendor", "cvss_score", "in_kev", "composite_score"]]
        .drop_duplicates(subset=["cve_id", "gi_software_name"])
        .reset_index(drop=True)
    )

    return gold_attributes


def save(gold_attributes, conn):
    gold_attributes.to_sql("gold_nvd_kev", conn, if_exists="replace", index=False)

if __name__ == "__main__":
    with sqlite3.connect(DB_PATH) as conn:
        silver = pd.read_sql("SELECT * FROM silver_nvd_kev", conn)
        gold_attributes = make_gold_table(silver)
        save(gold_attributes, conn)
