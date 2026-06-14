import re
import sqlite3
import pandas as pd
from pathlib import Path

DB_PATH = Path("./data/corpus.db")

STOP_WORDS = {
    "and", "or", "the", "for", "in", "of", "a", "an", "&",
    "enterprise", "professional", "standard",
    "business", "corporate", "community",
    "advanced", "premium", "plus", "pro",
    "edition", "suite", "apps", "application", "software", "solution",
    "service", "platform","client",
    "server", "desktop",
}


def meaningful_tokens(name: str):
    tokens = re.sub(r"[^\w\s]", " ", name.lower()).split()
    return {t for t in tokens if t not in STOP_WORDS and not t.isdigit()}


def tokenize_description(text: str):
    tokens = re.sub(r"[^\w\s]", " ", text.lower()).split()
    return set(tokens)


def match_nvd(conn):
    gi_df  = pd.read_sql("SELECT * FROM golden_image", conn)
    nvd_df = pd.read_sql("SELECT * FROM nvd_cves", conn)

    nvd_df["desc_tokens"] = nvd_df["description"].fillna("").apply(tokenize_description)

    #NVD token search
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
                "cvss_score":       nvd["cvss_score"],
                "cvss_severity":    nvd["cvss_severity"],
                "cve_description":  nvd["description"],
            })

    nvd_matches = pd.DataFrame(nvd_matches)

    return nvd_matches


def match_nvd_to_kev(conn, nvd_matches_df):
    kev_df = pd.read_sql("SELECT * FROM kev", conn)
    #KEV enrichment via cve_id join
    kev_small = kev_df[["cve_id", "product", "vuln_name", "date_added",
                        "due_date", "description", "required_action",
                        "knownRansomwareCampaignUse"]].copy()
    kev_small.columns = ["cve_id", "kev_product", "kev_vuln_name", "kev_date_added",
                        "kev_due_date", "kev_description", "kev_required_action",
                        "kev_ransomware"]

    nvd_kev = nvd_matches_df.merge(kev_small, on="cve_id", how="left")
    nvd_kev["in_kev"] = nvd_kev["kev_product"].notna()

    return nvd_kev


def save(nvd_kev, conn):
    nvd_kev.to_sql("silver_nvd_kev", conn, if_exists="replace", index=False)


if __name__ == "__main__":
    with sqlite3.connect(DB_PATH) as conn:
        nvd_matches = match_nvd(conn)
        nvd_kev_df = match_nvd_to_kev(conn, nvd_matches)
        save(nvd_kev_df, conn)
