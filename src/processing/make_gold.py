import sqlite3
import pandas as pd
from pathlib import Path

DB_PATH = Path("data/corpus.db")

#based on the golden image criticality
criticality_weight = {"Critical": 1.2, "High": 1, "Medium": 0.7, "Low": 0.3}


def make_gold_table(conn):
    silver = pd.read_sql("SELECT * FROM silver_nvd_kev", conn)

    silver["composite_score"] = (
        silver["cvss_score"].fillna(1)
        * silver["in_kev"].map({1: 1.5, 0: 1.0})
        * silver["gi_criticality"].map(criticality_weight)
    ).round(3)

    gold_attributes = (
        silver[["cve_id", "gi_software_name", "gi_vendor", "cvss_score", "in_kev", "composite_score"]]
        .drop_duplicates(subset=["cve_id", "gi_software_name"])
        .reset_index(drop=True)
    )

    return gold_attributes


def save(gold_attributes, conn):
    gold_attributes.to_sql("gold_nvd_kev", conn, if_exists="replace", index=False)

if __name__ == "__main__":
    with sqlite3.connect(DB_PATH) as conn:
        gold_attributes = make_gold_table(conn)
        save(gold_attributes, conn)
