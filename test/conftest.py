import pytest
import sqlite3
import pandas as pd
from pathlib import Path

TEST_DB_PATH = Path("test/data/test_corpus.db")


@pytest.fixture(autouse=True)
def setup_test_env():
    """Clean up test database before each test"""
    if TEST_DB_PATH.exists():
        TEST_DB_PATH.unlink()
    TEST_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    yield
    if TEST_DB_PATH.exists():
        TEST_DB_PATH.unlink()


@pytest.fixture
def test_db_connection():
    """Provide database connection for tests"""
    with sqlite3.connect(TEST_DB_PATH) as conn:
        yield conn
        conn.close()


@pytest.fixture
def golden_image_df():
    """Small golden image dataset for testing"""
    data = {
        "image_type": ["Corporate Workstation"],
        "category": ["Operating System"],
        "software_name": ["Windows 11 Enterprise"],
        "vendor": ["Microsoft"],
        "criticality": ["Critical"],
        "notes": ["Standard enterprise OS baseline"],
        "approved_version": ["23H2"]
    }
    return pd.DataFrame(data)


@pytest.fixture
def kev_data():
    """Mock KEV API response"""
    return {
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
                "shortDescription": "Heap buffer overflow in PDF parsing",
                "requiredAction": "Update to latest version",
                "dueDate": "2023-12-05",
                "notes": "Known exploit in wild"
            }
        ]
    }