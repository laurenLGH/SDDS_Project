import re
import pandas as pd
from config import STOP_WORDS


def meaningful_tokens(name: str):
    tokens = re.sub(r"[^\w\s]", " ", name.lower()).split()
    return {t for t in tokens if t not in STOP_WORDS and not t.isdigit()}


def tokenize_description(text: str):
    tokens = re.sub(r"[^\w\s]", " ", text.lower()).split()
    return set(tokens)


def match_nvd(gi_df, nvd_df):
    nvd_df["desc_tokens"] = nvd_df["description"].fillna("").apply(tokenize_description)

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

    return pd.DataFrame(nvd_matches)


def match_nvd_to_kev(nvd_matches_df, kev_df):
    kev_small = kev_df[["cve_id", "product", "vuln_name", "date_added",
                        "due_date", "description", "required_action",
                        "knownRansomwareCampaignUse"]].copy()
    kev_small.columns = ["cve_id", "kev_product", "kev_vuln_name", "kev_date_added",
                        "kev_due_date", "kev_description", "kev_required_action",
                        "kev_ransomware"]

    nvd_kev = nvd_matches_df.merge(kev_small, on="cve_id", how="left")
    nvd_kev["in_kev"] = nvd_kev["kev_product"].notna()

    return nvd_kev
