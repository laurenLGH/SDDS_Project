import pytest
import sqlite3
import pandas as pd
from pathlib import Path
import sys


project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


TEST_DB_PATH = Path("test/data/test_corpus.db")


@pytest.fixture(autouse=True)
def setup_test_env():
    """Clean up test database before and after each test"""
    # Clean up before test
    if TEST_DB_PATH.exists():
        TEST_DB_PATH.unlink()
    
    # Ensure directory exists
    TEST_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    yield
    
    # Clean up after test
    if TEST_DB_PATH.exists():
        TEST_DB_PATH.unlink()


@pytest.fixture
def test_db_connection():
    """Provide database connection for tests"""
    conn = sqlite3.connect(TEST_DB_PATH)
    try:
        yield conn
    finally:
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


@pytest.fixture
def nvd_data():
    """Mock NVD CVE data"""
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2023-1234",
                    "published": "2023-11-15T10:00:00.000",
                    "lastModified": "2023-11-16T14:30:00.000",
                    "descriptions": [
                        {"lang": "en", "value": "Windows kernel privilege escalation vulnerability"}
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
            }
        ]
    }


@pytest.fixture
def silver_data():
    """Sample silver table data for processing tests"""
    return {
        'cve_id': ['CVE-2023-1234', 'CVE-2023-5678'],
        'gi_software_name': ['Windows 11 Enterprise', 'SQL Server'],
        'gi_vendor': ['Microsoft', 'Microsoft'],
        'gi_criticality': ['Critical', 'Critical'],
        'approved_version': ['23H2', '2022'],
        'cvss_score': [9.8, 7.5],
        'in_kev': [1, 0],
        'cve_description': ['Windows vulnerability', 'SQL Server vulnerability'],
        'date_published': ['2023-11-15', '2023-11-20']
    }


@pytest.fixture
def setup_test_database():
    """Set up test database with sample data for integration tests"""
    # Clean up first
    if TEST_DB_PATH.exists():
        TEST_DB_PATH.unlink()
    
    # Create test database
    with sqlite3.connect(TEST_DB_PATH) as conn:
        # Golden image data
        golden_data = {
            "image_type": ["Corporate Workstation", "Server"],
            "category": ["Operating System", "Database"],
            "software_name": ["Windows 11 Enterprise", "SQL Server"],
            "vendor": ["Microsoft", "Microsoft"],
            "criticality": ["Critical", "Critical"],
            "notes": ["Standard OS", "Primary RDBMS"],
            "approved_version": ["23H2", "2022"]
        }
        pd.DataFrame(golden_data).to_sql("golden_image", conn, index=False)
        
        # NVD CVE data
        nvd_data = {
            "cve_id": ["CVE-2023-1234", "CVE-2023-5678"],
            "description": ["Microsoft Windows kernel vulnerability", "Microsoft SQL Server buffer overflow"],
            "cvss_score": [9.8, 7.5],
            "cvss_severity": ["Critical", "High"],
            "date_published": ["2023-11-15", "2023-11-20"]
        }
        pd.DataFrame(nvd_data).to_sql("nvd_cves", conn, index=False)
        
        # KEV data
        kev_data = {
            "cve_id": ["CVE-2023-1234"],
            "product": ["Windows 11"],
            "vuln_name": ["Windows Kernel Vuln"],
            "date_added": ["2023-11-15"],
            "due_date": ["2023-12-01"],
            "description": ["Windows vulnerability"],
            "required_action": ["Apply updates"],
            "knownRansomwareCampaignUse": ["Yes"]
        }
        pd.DataFrame(kev_data).to_sql("kev", conn, index=False)
    
    yield
    
    # Clean up after test
    if TEST_DB_PATH.exists():
        TEST_DB_PATH.unlink()