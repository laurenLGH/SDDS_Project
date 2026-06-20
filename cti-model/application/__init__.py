import io
import pandas as pd
from flask import Flask, request, Response, json
from config import NVD_CSV_PATH, KEV_CSV_PATH, BLOGS_CSV_PATH
from processing.make_silver import meaningful_tokens, tokenize_description
from processing.make_gold import make_gold_table

# load and pre-tokenize data once at startup
nvd_df = pd.read_csv(NVD_CSV_PATH)
kev_df = pd.read_csv(KEV_CSV_PATH)
blogs_df = pd.read_csv(BLOGS_CSV_PATH)

nvd_df["desc_tokens"] = nvd_df["description"].fillna("").apply(tokenize_description)
blogs_df["content_tokens"] = blogs_df["content"].fillna("").apply(tokenize_description)

app = Flask(__name__)


@app.route("/api", methods=["GET", "POST"])
def predict():
    gi_df = pd.read_json(io.StringIO(request.data.decode("utf-8")), orient="records")

    nvd_matches = []
    blog_matches = []
    seen_blogs = set()

    for _, gi in gi_df.iterrows():
        search_tokens = meaningful_tokens(gi["software_name"]) | {gi["vendor"].lower()}

        # match CVEs
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

        # match blogs
        blog_hits = blogs_df[blogs_df["content_tokens"].apply(lambda dt: search_tokens.issubset(dt))]
        for _, blog in blog_hits.iterrows():
            if blog["url"] not in seen_blogs:
                seen_blogs.add(blog["url"])
                blog_matches.append({
                    "gi_software_name": gi["software_name"],
                    "title":            blog["title"],
                    "source":           blog["source"],
                    "url":              blog["url"],
                    "date":             blog["date"],
                })

    nvd_matches_df = pd.DataFrame(nvd_matches)

    if nvd_matches_df.empty:
        return Response(json.dumps({"cves": [], "blogs": blog_matches}))

    kev_small = kev_df[["cve_id", "product", "vuln_name", "date_added",
                         "due_date", "description", "required_action",
                         "knownRansomwareCampaignUse"]].copy()
    kev_small.columns = ["cve_id", "kev_product", "kev_vuln_name", "kev_date_added",
                         "kev_due_date", "kev_description", "kev_required_action",
                         "kev_ransomware"]

    silver = nvd_matches_df.merge(kev_small, on="cve_id", how="left")
    silver["in_kev"] = silver["kev_product"].notna()

    gold = make_gold_table(silver)

    return Response(json.dumps({
        "cves":  gold.to_dict(orient="records"),
        "blogs": blog_matches
    }))
