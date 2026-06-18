import sqlite3
import pandas as pd
import pytest
from pathlib import Path

TEST_DB_PATH = Path("test/data/test_corpus.db")


@pytest.fixture
def setup_test_db():
    """Set up test database with sample data"""
    # Create test database
    with sqlite3.connect(TEST_DB_PATH) as conn:
        # Golden image data
        golden_data = {
            "image_type": ["Corporate Workstation", "Server"],
            "category": ["Operating System", "Database"],
            "software_name": ["Windows 11 Enterprise", "Microsoft SQL Server"],
            "vendor": ["Microsoft", "Microsoft"],
            "criticality": ["Critical", "Critical"],
            "notes": ["Standard OS", "Primary RDBMS"],
            "approved_version": ["23H2", "2022"]
        }
        pd.DataFrame(golden_data).to_sql("golden_image", conn, index=False)
        
        # NVD CVE data
        nvd_data = {
            "cve_id": ["CVE-2023-1234", "CVE-2023-5678", "CVE-2023-9012"],
            "description": [
                "Windows kernel privilege escalation vulnerability",
                "SQL Server buffer overflow vulnerability",
                "Linux kernel networking issue"
            ],
            "cvss_score": [9.8, 7.5, 3.2],
            "cvss_severity": ["Critical", "High", "Low"]
        }
        pd.DataFrame(nvd_data).to_sql("nvd_cves", conn, index=False)
        
        # KEV data
        kev_data = {
            "cve_id": ["CVE-2023-1234", "CVE-2023-5678"],
            "product": ["Windows 11", "SQL Server"],
            "vuln_name": ["Windows Kernel Vuln", "SQL Server Overflow"],
            "date_added": ["2023-11-15", "2023-11-20"],
            "due_date": ["2023-12-01", "2023-12-05"],
            "description": ["Windows vulnerability", "SQL Server vulnerability"],
            "required_action": ["Apply updates", "Update to latest"],
            "knownRansomwareCampaignUse": ["Yes", "No"]
        }
        pd.DataFrame(kev_data).to_sql("kev", conn, index=False)


def test_match_nvd_creates_matches(setup_test_db):
    """Verify NVD matching produces results"""
    from src.processing.make_silver import match_nvd
    
    with sqlite3.connect(TEST_DB_PATH) as conn:
        matches = match_nvd(conn)
        
    assert isinstance(matches, pd.DataFrame)
    assert len(matches) > 0, "Should find at least one NVD match"


def test_match_nvd_matches_by_tokens():
    """Test token-based matching logic"""
    from src.processing.make_silver import match_nvd
    
    with sqlite3.connect(TEST_DB_PATH) as conn:
        matches = match_nvd(conn)
    
    # Should match Windows 11 Enterprise -> Windows kernel
    windows_matches = matches[matches["gi_software_name"] == "Windows 11 Enterprise"]
    assert len(windows_matches) > 0, "Should match Windows-related CVEs"
    assert "Windows" in str(windows_matches.iloc[0]["cve_description"]), \
        "Matched CVE should contain Windows in description"


def test_match_nvd_filters_by_vendor():
    """Verify vendor filtering improves match accuracy"""
    from src.processing.make_silver import match_nvd
    
    with sqlite3.connect(TEST_DB_PATH) as conn:
        matches = match_nvd(conn)
    
    # Microsoft software should match Microsoft-related CVEs
    ms_matches = matches[matches["gi_vendor"] == "Microsoft"]
    assert len(ms_matches) > 0, "Should find Microsoft-related vulnerabilities"
    assert not ms_matches.empty, "Should have at least one Microsoft CVE match"


def test_match_nvd_to_kev_enriches_data(setup_test_db):
    """Test KEV enrichment adds columns to NVD matches"""
    from src.processing.make_silver import match_nvd, match_nvd_to_kev
    
    with sqlite3.connect(TEST_DB_PATH) as conn:
        nvd_matches = match_nvd(conn)
        nvd_kev = match_nvd_to_kev(conn, nvd_matches)
    
    # Should have KEV-specific columns
    kev_columns = ["kev_product", "kev_vuln_name", "kev_date_added", 
                   "kev_due_date", "kev_required_action", "kev_ransomware"]
    assert all(col in nvd_kev.columns for col in kev_columns), \
        f"Missing KEV columns: {set(kev_columns) - set(nvd_kev.columns)}"


def test_match_nvd_to_kev_identifies_in_kev_flag(setup_test_db):
    """Verify in_kev flag correctly identifies KEV-listed CVEs"""
    from src.processing.make_silver import match_nvd, match_nvd_to_kev
    
    with sqlite3.connect(TEST_DB_PATH) as conn:
        nvd_matches = match_nvd(conn)
        nvd_kev = match_nvd_to_kev(conn, nvd_matches)
    
    # CVE-2023-1234 and CVE-2023-5678 should be in KEV
    kev_cves = set(nvd_kev[nvd_kev["in_kev"] == True]["cve_id"])
    assert "CVE-2023-1234" in kev_cves, "CVE-2023-1234 should be marked as in KEV"
    assert "CVE-2023-5678" in kev_cves, "CVE-2023-5678 should be marked as in KEV"


def test_save_creates_silver_table(setup_test_db):
    """Verify save function creates silver table"""
    from src.processing.make_silver import match_nvd, match_nvd_tokev, save
    
    with sqlite3.connect(TEST_DB_PATH) as conn:
        nvd_matches = match_nvd(conn)
        nvd_kev = match_nvd_to_kev(conn, nvd_matches)
        save(nvd_kev, conn)
    
    # Verify table exists and has data
    result_df = pd.read_sql("SELECT * FROM silver_nvd_kev", conn)
    assert len(result_df) > 0, "Silver table should contain records"
    assert len(result_df) == len(nvd_kev), "Silver table row count should match input"


def test_stop_words_filtering():
    """Test that stop words are properly filtered from tokens"""
    from src.processing.make_silver import meaningful_tokens
    
    test_cases = [
        ("Microsoft Windows 11 Enterprise", {"microsoft", "windows", "11"}),
        ("Adobe Acrobat Reader", {"adobe", "acrobat", "reader"}),
        ("Microsoft SQL Server 2022", {"microsoft", "sql", "server", "2022"})
    ]
    
    for text, expected in test_cases:
        result = meaningful_tokens(text)
        assert result == expected, f"Failed for '{text}': got {result}, expected {expected}"


def test_stop_words_excludes_common_words():
    """Verify stop words list filters out common terms"""
    from src.processing.make_silver import STOP_WORDS
    
    common_words = {"the", "and", "for", "in", "of", "a", "an"}
    assert common_words.issubset(STOP_WORDS), "Stop words should contain common words"


def test_stop_words_handles_case_insensitivity():
    """Test tokenization handles case properly"""
    from src.processing.make_silver import tokenize_description
    
    text = "Windows Kernel VULNERABILITY"
    tokens = tokenize_description(text)
    assert "windows" in tokens, "Should lowercase tokens"
    assert "kernel" in tokens, "Should preserve meaningful words"
    assert "vulnerability" in tokens, "Should preserve technical terms"


def test_match_nvd_handles_empty_nvd_data(setup_test_db):
    """Verify graceful handling when NVD data is empty"""
    from src.processing.make_silver import match_nvd
    
    # Clear NVD table
    with sqlite3.connect(TEST_DB_PATH) as conn:
        conn.execute("DELETE FROM nvd_cves")
        matches = match_nvd(conn)
    
    assert isinstance(matches, pd.DataFrame)
    assert len(matches) == 0, "Should return empty DataFrame for empty NVD"


def test_match_nvd_handles_missing_descriptions(setup_test_db):
    """Verify handling of NULL/empty CVE descriptions"""
    from src.processing.make_silver import match_nvd
    
    # Add CVE with missing description
    with sqlite3.connect(TEST_DB_PATH) as conn:
        conn.execute(
            "INSERT INTO nvd_cves (cve_id, description, cvss_score, cvss_severity) VALUES (?, ?, ?, ?)",
            ("CVE-2023-9999", None, 5.0, "Medium")
        )
        matches = match_nvd(conn)
    
    # Should not crash on NULL descriptions
    assert isinstance(matches, pd.DataFrame)


def test_match_nvd_to_kev_handles_missing_kev_data(setup_test_db):
    """Verify graceful handling when KEV data is missing"""
    from src.processing.make_silver import match_nvd, match_nvd_to_kev
    
    # Clear KEV table
    with sqlite3.connect(TEST_DB_PATH) as conn:
        conn.execute("DELETE FROM kev")
        nvd_matches = match_nvd(conn)
        nvd_kev = match_nvd_to_kev(conn, nvd_matches)
    
    # Should still work with left join
    assert "in_kev" in nvd_kev.columns
    assert all(nvd_kev["in_kev"] == False), "All matches should be marked as not in KEV"


def test_silver_schema_validation(setup_test_db):
    """Verify silver table has expected schema"""
    from src.processing.make_silver import match_nvd, match_nvd_to_kev, save
    
    with sqlite3.connect(TEST_DB_PATH) as conn:
        nvd_matches = match_nvd(conn)
        nvd_kev = match_nvd_to_kev(conn, nvd_matches)
        save(nvd_kev, conn)
        
        # Verify schema
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(silver_nvd_kev)")
        columns = {row[1] for row in cursor.fetchall()}
        
        expected_columns = {
            "gi_software_name", "gi_vendor", "gi_criticality", "approved_version",
            "cve_id", "cvss_score", "cvss_severity", "cve_description",
            "kev_product", "kev_vuln_name", "kev_date_added", "kev_due_date",
            "kev_description", "kev_required_action", "kev_ransomware", "in_kev"
        }
        assert columns == expected_columns, f"Schema mismatch: {columns ^ expected_columns}"