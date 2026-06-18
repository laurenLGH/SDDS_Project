import sqlite3
import sys
import json
import requests
import pandas as pd
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))
from config import DB_PATH, NVD_DAYS_BACK as DAYS_BACK

NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0'


def get_nvd(days_back: int = DAYS_BACK) -> pd.DataFrame:
    end_date   = pd.Timestamp.today()
    start_date = end_date - pd.Timedelta(days=days_back)

    params = {
        'pubStartDate'  : start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
        'pubEndDate'    : end_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
        'resultsPerPage': 2000,
        'startIndex'    : 0,
    }

    resp = requests.get(NVD_BASE, params=params)
    resp.raise_for_status()
    nvd_raw = resp.json()

    df = pd.json_normalize(nvd_raw['vulnerabilities'])
    return df


def store_nvd(df: pd.DataFrame):
    rows = []
    for _, row in df.iterrows():
        rows.append({
            'cve_id'        : row.get('cve.id'),
            'date_published': str(row.get('cve.published', ''))[:10],
            'date_modified' : str(row.get('cve.lastModified', ''))[:10],
            'description'   : next(
                (d['value'] for d in (row.get('cve.descriptions') or []) if d.get('lang') == 'en'),
                ''
            ),
            'cvss_score'    : (
                metric[0].get('cvssData', {}).get('baseScore')
                if isinstance(metric := row.get('cve.metrics.cvssMetricV31'), list) and metric
                else None
            ),
            'cvss_severity' : (
                metric[0].get('cvssData', {}).get('baseSeverity')
                if isinstance(metric := row.get('cve.metrics.cvssMetricV31'), list) and metric
                else None
            ),
        })

    clean_df = pd.DataFrame(rows).dropna(subset=['cve_id'])

    with sqlite3.connect(DB_PATH) as conn:
        clean_df.to_sql('nvd_cves', conn, if_exists='replace', index=False)

if __name__ == '__main__':
    store_nvd(get_nvd())
