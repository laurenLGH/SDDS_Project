import json
import pytest
import requests
from unittest.mock import Mock, patch
import sqlite3
import pandas as pd

from src.ingestion.kev import fetch_kev, store_kev

MOCK_KEV_DATA = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2023-1234",
            "vendorProject": "Microsoft",
            "product": "Windows 11",
            "vulnerabilityName": "Windows Elevation Vulnerability",
            "dateAdded": "2023-11-15",
            "shortDescription": "Critical vulnerability in Windows kernel",
            "requiredAction": "Apply updates",
            "dueDate": "2023-12-01",
            "notes": "Test vulnerability"
        },
        {
            "cveID": "CVE-2023-5678",
            "vendorProject": "Adobe",
            "product": "Acrobat Reader",
            "vulnerabilityName": "PDF Parser Vulnerability",
            "dateAdded": "2023-11-20",
            "shortDescription": "Heap buffer overflow",
            "requiredAction": "Update to latest version",
            "dueDate": "2023-12-05",
            "notes": "Known exploit in wild"
        }
    ]
}


def test_fetch_kev_mock_success():
    """Test KEV fetch with mocked API response"""
    with patch('src.ingestion.kev.requests.get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = MOCK_KEV_DATA
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        df = fetch_kev()
        
        assert isinstance(df, pd.DataFrame)
        assert len(df) == len(MOCK_KEV_DATA["vulnerabilities"])


def test_fetch_kev_renames_columns_correctly():
    """Verify column mapping from API to canonical format"""
    with patch('src.ingestion.kev.requests.get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = MOCK_KEV_DATA
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        df = fetch_kev()
        expected_columns = [
            "cve_id", "vendor", "product", "vuln_name", "date_added",
            "description", "required_action", "due_date", "notes"
        ]
        assert all(col in df.columns for col in expected_columns)


def test_fetch_kev_missing_vulnerabilities_key_raises_error():
    """Ensure proper error handling when API response is malformed"""
    malformed_data = {"invalid_key": "data"}
    
    with patch('src.ingestion.kev.requests.get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = malformed_data
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        try:
            fetch_kev()
            assert False, "Should have raised KeyError"
        except KeyError:
            pass  # Expected behavior


def test_store_kev_creates_table(test_db_connection):
    """Verify store_kev creates the database table"""
    df = pd.DataFrame(MOCK_KEV_DATA["vulnerabilities"])
    
    # Temporarily adjust module DB_PATH
    import src.ingestion.kev as kev_module
    original_path = kev_module.DB_PATH
    kev_module.DB_PATH = test_db_connection
    store_kev(df)
    kev_module.DB_PATH = original_path
    
    cursor = test_db_connection.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='kev'")
    assert cursor.fetchone() is not None


def test_store_kev_converts_list_dict_to_json():
    """Verify complex data types are serialized to JSON strings"""
    test_data = MOCK_KEV_DATA.copy()
    test_data["vulnerabilities"][0]["notes"] = ["note1", "note2"]  # List
    test_data["vulnerabilities"][1]["notes"] = {"key": "value"}    # Dict
    
    df = pd.DataFrame(test_data["vulnerabilities"])
    
    # Temporarily adjust module DB_PATH
    import src.ingestion.kev as kev_module
    original_path = kev_module.DB_PATH
    kev_module.DB_PATH = test_db_connection
    store_kev(df)
    kev_module.DB_PATH = original_path
    
    result_df = pd.read_sql("SELECT * FROM kev", test_db_connection)
    # Verify notes are now strings
    assert isinstance(result_df.loc[0, "notes"], str)
    assert isinstance(result_df.loc[1, "notes"], str)


def test_store_kev_handles_empty_vulnerabilities():
    """Verify empty vulnerability list doesn't cause errors"""
    empty_data = {"vulnerabilities": []}
    
    with patch('src.ingestion.kev.requests.get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = empty_data
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        df = fetch_kev()
        
        assert isinstance(df, pd.DataFrame)
        assert len(df) == 0


def test_kev_data_validation():
    """Test that KEV data meets minimum validation requirements"""
    with patch('src.ingestion.kev.requests.get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = MOCK_KEV_DATA
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        df = fetch_kev()
        
        # Required fields should not be null
        required_fields = ["cve_id", "description", "date_added"]
        for field in required_fields:
            assert not df[field].isnull().any(), f"Null values in required field: {field}"