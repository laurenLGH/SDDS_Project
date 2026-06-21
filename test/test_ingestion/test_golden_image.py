import sqlite3
import pandas as pd
from pathlib import Path
from conftest import TEST_DB_PATH
# Test against the actual file but use a test database
from src.ingestion.golden_image import fetch_golden_image, store_golden_image

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


def test_store_golden_image_creates_table():
    """Verify store_golden_image creates the database table"""
    df = fetch_golden_image()
    
    # Use the TEST_DB_PATH constant
    store_golden_image(df, db_path=TEST_DB_PATH)
    
    # Use a fresh connection for verification
    with sqlite3.connect(TEST_DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='golden_image'")
        assert cursor.fetchone() is not None

def test_store_golden_image_data_integrity():
    """Ensure data is stored correctly with same row count"""
    df = fetch_golden_image()
    
    # Use the TEST_DB_PATH constant
    store_golden_image(df, db_path=TEST_DB_PATH)
    
    # Use a fresh connection for reading
    with sqlite3.connect(TEST_DB_PATH) as conn:
        result_df = pd.read_sql("SELECT * FROM golden_image", conn)
        assert len(result_df) == len(df), "Row count mismatch after storing golden image"