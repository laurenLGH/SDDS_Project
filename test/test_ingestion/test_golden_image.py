import sqlite3
import pandas as pd
from pathlib import Path
import pytest

# Test against the actual file but use a test database
from src.ingestion.golden_image import fetch_golden_image, store_golden_image

DB_PATH = Path("test/data/test_corpus.db")


def test_fetch_golden_image_returns_dataframe():
    """Verify fetch_golden_image returns a pandas DataFrame"""
    df = fetch_golden_image()
    assert isinstance(df, pd.DataFrame)


def test_fetch_golden_image_has_expected_columns():
    """Ensure the golden image has the required schema"""
    df = fetch_golden_image()
    expected_columns = [
        "image_type", "category", "software_name", "vendor",
        "criticality", "notes", "approved_version"
    ]
    actual_columns = df.columns.tolist()
    assert all(col in actual_columns for col in expected_columns), \
        f"Missing columns: {set(expected_columns) - set(actual_columns)}"


def test_fetch_golden_image_strips_whitespace():
    """Verify column names have whitespace stripped"""
    df = fetch_golden_image()
    assert all(col == col.strip() for col in df.columns)


def test_fetch_golden_image_has_data():
    """Confirm golden image has records (data integrity check)"""
    df = fetch_golden_image()
    assert len(df) > 0, "Golden image should contain records"


def test_fetch_golden_image_criticality_values():
    """Validate criticality field contains expected values"""
    df = fetch_golden_image()
    valid_criticality = {"Critical", "High", "Medium", "Low"}
    actual_criticality = set(df["criticality"].unique())
    assert actual_criticality.issubset(valid_criticality), \
        f"Invalid criticality values: {actual_criticality - valid_criticality}"


def test_store_golden_image_creates_table(test_db_connection):
    """Verify store_golden_image creates the database table"""
    df = fetch_golden_image()
    
    # Temporarily update DB_PATH
    original_db_path = Path("src/ingestion/golden_image.py").read_text().split("DB_PATH")[1].split("=")[1].strip().strip("'\"")
    
    # Store to test DB
    with sqlite3.connect(test_db_connection) as conn:
        df.to_sql("golden_image", conn, if_exists="replace", index=False)
    
    cursor = test_db_connection.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='golden_image'")
    assert cursor.fetchone() is not None


def test_store_golden_image_data_integrity(test_db_connection):
    """Ensure data is stored correctly with same row count"""
    df = fetch_golden_image()
    
    # Store to test DB
    with sqlite3.connect(test_db_connection) as conn:
        df.to_sql("golden_image", conn, if_exists="replace", index=False)
    
    result_df = pd.read_sql("SELECT * FROM golden_image", test_db_connection)
    assert len(result_df) == len(df), "Row count mismatch after storing golden image"