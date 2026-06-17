import sys
import io
import sqlite3
from pathlib import Path
from flask import Flask, request, Response, json
import pandas as pd

sys.path.append(str(Path(__file__).resolve().parents[2]))
from processing.make_silver import meaningful_tokens, tokenize_description, match_nvd_to_kev
from processing.make_gold import make_gold_table
from config import DB_PATH

# load and pre-tokenize NVD and KEV data once at startup
with sqlite3.connect(DB_PATH) as conn:
    nvd_df = pd.read_sql("SELECT * FROM nvd_cves", conn)
    kev_df = pd.read_sql("SELECT * FROM kev", conn)

nvd_df["desc_tokens"] = nvd_df["description"].fillna("").apply(tokenize_description)

app = Flask(__name__)


@app.route("/api", methods=["GET", "POST"])
def predict():
    gi_df = pd.read_json(io.StringIO(request.data.decode("utf-8")), orient="records")

    nvd_matches = []
    for _, gi in gi_df.iterrows():
        search_tokens = meaningful_tokens(gi["software_name"]) | {gi["vendor"].lower()}
        matches = nvd_df[nvd_df["desc_tokens"].apply(lambda dt: search_tokens.issubset(dt))]
        for _, nvd in matches.iterrows():
            nvd_matches.append({
                "gi_software_name": gi["software_name"],
                "gi_vendor":        gi["vendor"],
                "gi_criticality":   gi["criticality"],
                "approved_version": gi["approved_version"],
                "cve_id":           nvd["cve_id"],
                "date_published":   nvd["date_published"],
                "cvss_score":       nvd["cvss_score"],
                "cvss_severity":    nvd["cvss_severity"],
                "cve_description":  nvd["description"],
            })

    nvd_matches_df = pd.DataFrame(nvd_matches)

    if nvd_matches_df.empty:
        return Response(json.dumps([]))

    kev_small = kev_df[["cve_id", "product", "vuln_name", "date_added",
                         "due_date", "description", "required_action",
                         "knownRansomwareCampaignUse"]].copy()
    kev_small.columns = ["cve_id", "kev_product", "kev_vuln_name", "kev_date_added",
                         "kev_due_date", "kev_description", "kev_required_action",
                         "kev_ransomware"]

    silver = nvd_matches_df.merge(kev_small, on="cve_id", how="left")
    silver["in_kev"] = silver["kev_product"].notna()

    gold = make_gold_table(silver)

    return Response(json.dumps(gold.to_dict(orient="records")))
