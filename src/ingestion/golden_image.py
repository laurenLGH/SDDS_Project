import sqlite3
import sys
from pathlib import Path
import pandas as pd

sys.path.append(str(Path(__file__).resolve().parents[1]))
from config import DB_PATH, GOLDEN_IMAGE_PATH


def fetch_golden_image():
    assert GOLDEN_IMAGE_PATH.exists(), "File not found"
    try:
        df = pd.read_csv(GOLDEN_IMAGE_PATH)
        df.columns = df.columns.str.strip()
        return df
    except Exception as e:
        print(f"Error reading golden image: {e} use a .CSV only")
        return pd.DataFrame()



def store_golden_image(df: pd.DataFrame, db_path=DB_PATH):
    with sqlite3.connect(db_path) as conn:
        df.to_sql('golden_image', conn, if_exists='replace', index=False)


if __name__ == '__main__':
    store_golden_image(fetch_golden_image())
