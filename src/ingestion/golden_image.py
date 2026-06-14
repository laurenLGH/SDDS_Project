import sqlite3
import pandas as pd
from pathlib import Path

DB_PATH           = Path('data/corpus.db')
GOLDEN_IMAGE_PATH = Path('data/golden_image.csv')


def fetch_golden_image():
    df = pd.read_csv(GOLDEN_IMAGE_PATH)
    df.columns = df.columns.str.strip()
    return df


def store_golden_image(df: pd.DataFrame):
    with sqlite3.connect(DB_PATH) as conn:
        df.to_sql('golden_image', conn, if_exists='replace', index=False)


if __name__ == '__main__':
    store_golden_image(fetch_golden_image())
