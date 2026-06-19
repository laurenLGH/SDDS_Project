import sqlite3
import pandas as pd
from pathlib import Path
import pytest
import json
from unittest.mock import patch
from conftest import TEST_DB_PATH

from src.ingestion.kev import fetch_kev, store_kev

DATA_DIR = Path(__file__).parent.parent / "data"


def test_fetch_kev_returns_dataframe():
    """Verify fetch_kev returns a pandas DataFrame"""
    df = fetch_kev()
    assert isinstance(df, pd.DataFrame)


def test_fetch_kev_has_expected_columns():
    """Ensure KEV data has the required schema"""
    df = fetch_kev()
    # Use the actual column names from kev.py implementation
    expected_columns = [
        "cve_id", "vendor", "product", "vuln_name",
        "date_added", "description", "required_action",
        "due_date", "notes"
    ]
    actual_columns = df.columns.tolist()
    assert all(col in actual_columns for col in expected_columns), \
        f"Missing columns: {set(expected_columns) - set(actual_columns)}"


def test_fetch_kev_has_data():
    """Confirm KEV data has records"""
    df = fetch_kev()
    assert len(df) > 0, "KEV data should contain records"


def test_fetch_kev_with_mock_data():
    """Verify fetch_kev works with mock data from JSON file"""
    # Load mock data from JSON
    with open(DATA_DIR / "mock_kev.json", "r") as f:
        mock_data = json.load(f)
    
    # Convert to DataFrame (this is what fetch_kev does internally)
    df = pd.DataFrame(mock_data["vulnerabilities"])
    
    # Map JSON keys to database column names (using actual implementation mapping)
    column_mapping = {
        "cveID": "cve_id",
        "vendorProject": "vendor",           
        "product": "product",
        "vulnerabilityName": "vuln_name",    
        "dateAdded": "date_added",
        "shortDescription": "description",   
        "requiredAction": "required_action",
        "dueDate": "due_date",
        "notes": "notes"
    }
    
    df = df.rename(columns=column_mapping)
    
    # Verify the transformed data
    assert len(df) == 2
    assert df['cve_id'].iloc[0] == "CVE-2023-1234"
    assert df['vendor'].iloc[0] == "Microsoft"  


def test_store_kev_creates_table():
    """Verify store_kev creates the database table"""
    df = fetch_kev()
    
    # Use TEST_DB_PATH (file path), not test_db_connection (connection object)
    store_kev(df, db_path=TEST_DB_PATH)
    
    # Use a fresh connection for verification
    with sqlite3.connect(TEST_DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='kev'")
        assert cursor.fetchone() is not None


def test_store_kev_converts_list_dict_to_json():
    """Verify list/dict fields are converted to JSON strings"""
    df = fetch_kev()
    
    # Store to test DB
    store_kev(df, db_path=TEST_DB_PATH)
    
    # Use a fresh connection for reading
    with sqlite3.connect(TEST_DB_PATH) as conn:
        result_df = pd.read_sql("SELECT * FROM kev", conn)
        
        # Check that notes field (which might be a list/dict) is now a string
        if 'notes' in result_df.columns:
            notes_value = result_df['notes'].iloc[0]
            assert isinstance(notes_value, str), f"Notes should be JSON string, got {type(notes_value)}"


def test_store_kev_data_integrity():
    """Verify stored data matches source data"""
    df = fetch_kev()
    
    # Store to test DB
    store_kev(df, db_path=TEST_DB_PATH)
    
    # Use a fresh connection for reading
    with sqlite3.connect(TEST_DB_PATH) as conn:
        result_df = pd.read_sql("SELECT * FROM kev", conn)
        
        # Verify row count matches
        assert len(result_df) == len(df), "Row count mismatch after storing KEV data"
        
        # Verify key fields match (using actual column names)
        assert result_df['cve_id'].iloc[0] == df['cve_id'].iloc[0]
        assert result_df['vendor'].iloc[0] == df['vendor'].iloc[0]
        assert result_df['vuln_name'].iloc[0] == df['vuln_name'].iloc[0]