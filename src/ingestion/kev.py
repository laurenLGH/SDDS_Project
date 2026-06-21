import sqlite3
import sys
import json
import requests
import pandas as pd
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))
from config import DB_PATH
KEV_URL  = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'


def fetch_kev():
    resp = requests.get(KEV_URL, timeout=30)
    resp.raise_for_status()
    kev_raw = resp.json()

    df = pd.DataFrame(kev_raw['vulnerabilities'])
    df = df.rename(columns={
        'cveID'             : 'cve_id',
        'vendorProject'     : 'vendor',
        'product'           : 'product',
        'vulnerabilityName' : 'vuln_name',
        'dateAdded'         : 'date_added',
        'shortDescription'  : 'description',
        'requiredAction'    : 'required_action',
        'dueDate'           : 'due_date',
        'notes'             : 'notes',
    })

    return df


def store_kev(df: pd.DataFrame, db_path=DB_PATH):
    #convert any list/dict columns to JSON strings
    for col in df.columns:
        if df[col].apply(lambda x: isinstance(x, (list, dict))).any():
            df[col] = df[col].apply(lambda x: json.dumps(x) if isinstance(x, (list, dict)) else x)

    with sqlite3.connect(db_path) as conn:
        df.to_sql('kev', conn, if_exists='replace', index=False)


if __name__ == '__main__':
    store_kev(fetch_kev())
