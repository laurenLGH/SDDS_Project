import pytest
import pandas as pd
from unittest.mock import Mock, patch
import sqlite3

from src.ingestion.nvd import get_nvd, store_nvd

MOCK_NVD_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2023-1234",
                "published": "2023-11-15T10:00:00.000",
                "lastModified": "2023-11-16T14:30:00.000",
                "descriptions": [
                    {"lang": "en", "value": "Windows kernel privilege escalation vulnerability"},
                    {"lang": "es", "value": "Vulnerabilidad de escalación de privilegios"}
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL"
                            }
                        }
                    ]
                }
            }
        },
        {
            "cve": {
                "id": "CVE-2023-5678",
                "published": "2023-11-20T08:00:00.000",
                "lastModified": "2023-11-21T09:00:00.000",
                "descriptions": [
                    {"lang": "en", "value": "SQL Server buffer overflow vulnerability"}
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH"
                            }
                        }
                    ]
                }
            }
        },
        {
            "cve": {
                "id": "CVE-2023-9012",
                "published": "2023-11-25T12:00:00.000",
                "lastModified": "2023-11-26T11:00:00.000",
                "descriptions": [
                    {"lang": "en", "value": "Linux kernel networking issue"}
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 3.2,
                                "baseSeverity": "LOW"
                            }
                        }
                    ]
                }
            }
        }
    ]
}


def test_get_nvd_returns_dataframe():
    """Verify get_nvd returns a pandas DataFrame"""
    with patch('src.ingestion.nvd.requests.get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = MOCK_NVD_RESPONSE
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        df = get_nvd()
        
        assert isinstance(df, pd.DataFrame)


def test_get_nvd_has_expected_columns():
    """Ensure NVD data has the expected structure"""
    with patch('src.ingestion.nvd.requests.get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = MOCK_NVD_RESPONSE
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        df = get_nvd()
        
        # Check that we have the expected CVE structure
        assert len(df) == 3, "Should have 3 CVE entries"
        assert 'cve.id' in df.columns, "Should have cve.id column"


def test_get_nvd_date_range_parameters():
    """Verify date parameters are correctly formatted"""
    with patch('src.ingestion.nvd.requests.get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = MOCK_NVD_RESPONSE
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        get_nvd(days_back=5)
        
        # Check that the request was called with correct date parameters
        call_args = mock_get.call_args
        params = call_args[1]['params']
        
        assert 'pubStartDate' in params
        assert 'pubEndDate' in params
        assert params['resultsPerPage'] == 2000
        assert params['startIndex'] == 0


def test_store_nvd_creates_table(test_db_connection):
    """Verify store_nvd creates the database table"""
    with patch('src.ingestion.nvd.requests.get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = MOCK_NVD_RESPONSE
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        df = get_nvd()
        store_nvd(df)
    
    cursor = test_db_connection.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='nvd_cves'")
    assert cursor.fetchone() is not None


def test_store_nvd_has_correct_schema():
    """Verify NVD table has the expected columns"""
    with patch('src.ingestion.nvd.requests.get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = MOCK_NVD_RESPONSE
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        df = get_nvd()
        store_nvd(df)
    
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(nvd_cves)")
        columns = {row[1] for row in cursor.fetchall()}
        
        expected_columns = {
            'cve_id', 'date_published', 'date_modified', 
            'description', 'cvss_score', 'cvss_severity'
        }
        assert columns == expected_columns, f"Schema mismatch: {columns ^ expected_columns}"


def test_store_nvd_extract_en_description():
    """Verify English description is extracted correctly"""
    with patch('src.ingestion.nvd.requests.get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = MOCK_NVD_RESPONSE
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        df = get_nvd()
        store_nvd(df)
    
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        result_df = pd.read_sql("SELECT * FROM nvd_cves", conn)
        
        # Should extract English description, not Spanish
        windows_desc = result_df[result_df['cve_id'] == 'CVE-2023-1234']['description'].iloc[0]
        assert 'Windows kernel' in windows_desc
        assert 'escalación' not in windows_desc  # Spanish text should not be included


def test_store_nvd_handles_missing_cvss():
    """Verify graceful handling when CVSS data is missing"""
    nvd_data_missing_cvss = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2023-9999",
                    "published": "2023-11-15T10:00:00.000",
                    "lastModified": "2023-11-16T14:30:00.000",
                    "descriptions": [
                        {"lang": "en", "value": "Vulnerability with no CVSS data"}
                    ],
                    "metrics": {}
                }
            }
        ]
    }
    
    with patch('src.ingestion.nvd.requests.get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = nvd_data_missing_cvss
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        df = get_nvd()
        store_nvd(df)
    
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        result_df = pd.read_sql("SELECT * FROM nvd_cves", conn)
        
        # Should have NULL values for missing CVSS
        row = result_df[result_df['cve_id'] == 'CVE-2023-9999']
        assert row['cvss_score'].isna().any()
        assert row['cvss_severity'].isna().any()


def test_store_nvd_handles_empty_vulnerabilities():
    """Verify handling of empty vulnerability list"""
    empty_response = {"vulnerabilities": []}
    
    with patch('src.ingestion.nvd.requests.get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = empty_response
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        df = get_nvd()
        store_nvd(df)
    
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        result_df = pd.read_sql("SELECT * FROM nvd_cves", conn)
        assert len(result_df) == 0


def test_store_nvd_drops_rows_without_cve_id():
    """Verify rows without CVE ID are dropped"""
    nvd_data_missing_id = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2023-1234",
                    "published": "2023-11-15T10:00:00.000",
                    "lastModified": "2023-11-16T14:30:00.000",
                    "descriptions": [{"lang": "en", "value": "Valid CVE"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}
                }
            },
            {
                "cve": {
                    "published": "2023-11-15T10:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Missing ID"}]
                }
            }
        ]
    }
    
    with patch('src.ingestion.nvd.requests.get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = nvd_data_missing_id
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        df = get_nvd()
        store_nvd(df)
    
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        result_df = pd.read_sql("SELECT * FROM nvd_cves", conn)
        assert len(result_df) == 1, "Should drop row without CVE ID"
        assert result_df['cve_id'].iloc[0] == 'CVE-2023-1234'


def test_store_nvd_date_format():
    """Verify dates are stored in YYYY-MM-DD format"""
    with patch('src.ingestion.nvd.requests.get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = MOCK_NVD_RESPONSE
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        df = get_nvd()
        store_nvd(df)
    
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        result_df = pd.read_sql("SELECT * FROM nvd_cves", conn)
        
        # Check date format
        for _, row in result_df.iterrows():
            assert len(row['date_published']) == 10, "Date should be YYYY-MM-DD format"
            assert row['date_published'][4] == '-', "Date should have hyphens"


def test_store_nvd_cvss_score_extraction():
    """Verify CVSS score is correctly extracted from nested structure"""
    with patch('src.ingestion.nvd.requests.get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = MOCK_NVD_RESPONSE
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        df = get_nvd()
        store_nvd(df)
    
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        result_df = pd.read_sql("SELECT * FROM nvd_cves", conn)
        
        # Check CVSS scores
        scores = dict(zip(result_df['cve_id'], result_df['cvss_score']))
        assert scores['CVE-2023-1234'] == 9.8
        assert scores['CVE-2023-5678'] == 7.5
        assert scores['CVE-2023-9012'] == 3.2


def test_store_nvd_cvss_severity_extraction():
    """Verify CVSS severity is correctly extracted"""
    with patch('src.ingestion.nvd.requests.get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = MOCK_NVD_RESPONSE
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        df = get_nvd()
        store_nvd(df)
    
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        result_df = pd.read_sql("SELECT * FROM nvd_cves", conn)
        
        # Check CVSS severities
        severities = dict(zip(result_df['cve_id'], result_df['cvss_severity']))
        assert severities['CVE-2023-1234'] == 'CRITICAL'
        assert severities['CVE-2023-5678'] == 'HIGH'
        assert severities['CVE-2023-9012'] == 'LOW'


def test_get_nvd_default_days_back():
    """Verify default days_back parameter works correctly"""
    with patch('src.ingestion.nvd.requests.get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = MOCK_NVD_RESPONSE
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        get_nvd()  # Use default
        
        # Should use default DAYS_BACK = 10
        call_args = mock_get.call_args
        params = call_args[1]['params']
        assert 'pubStartDate' in params
        assert 'pubEndDate' in params


def test_store_nvd_data_integrity():
    """Verify data integrity after storage"""
    with patch('src.ingestion.nvd.requests.get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = MOCK_NVD_RESPONSE
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        df = get_nvd()
        store_nvd(df)
        
        # Store again to test replace behavior
        store_nvd(df)
    
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        result_df = pd.read_sql("SELECT * FROM nvd_cves", conn)
        
        # Should have same data after replace
        assert len(result_df) == 3
        assert set(result_df['cve_id']) == {'CVE-2023-1234', 'CVE-2023-5678', 'CVE-2023-9012'}


