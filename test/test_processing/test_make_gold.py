import pytest
import pandas as pd
import sqlite3

from src.processing.make_gold import make_gold_table, save, criticality_weight


@pytest.fixture
def setup_silver_data():
    """Set up test database with silver data"""
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        # Create silver_nvd_kev table with test data
        silver_data = {
            'cve_id': ['CVE-2023-1234', 'CVE-2023-1234', 'CVE-2023-5678', 'CVE-2023-9012'],
            'gi_software_name': ['Windows 11 Enterprise', 'Windows 11 Enterprise', 'SQL Server', 'Linux Kernel'],
            'gi_vendor': ['Microsoft', 'Microsoft', 'Microsoft', 'Linux'],
            'gi_criticality': ['Critical', 'Critical', 'Critical', 'High'],
            'approved_version': ['23H2', '23H2', '2022', '5.15'],
            'cvss_score': [9.8, 9.8, 7.5, 6.5],
            'in_kev': [1, 1, 0, 0],
            'cve_description': ['Windows vulnerability', 'Windows vulnerability', 'SQL Server vulnerability', 'Linux vulnerability'],
            'kev_product': ['Windows 11', 'Windows 11', None, None],
            'kev_vuln_name': ['Windows Vuln', 'Windows Vuln', None, None],
            'kev_date_added': ['2023-11-15', '2023-11-15', None, None],
            'kev_due_date': ['2023-12-01', '2023-12-01', None, None],
            'kev_description': ['Windows vulnerability', 'Windows vulnerability', None, None],
            'kev_required_action': ['Apply updates', 'Apply updates', None, None],
            'kev_ransomware': ['Yes', 'Yes', None, None]
        }
        pd.DataFrame(silver_data).to_sql('silver_nvd_kev', conn, index=False)


def test_make_gold_table_returns_dataframe(setup_silver_data):
    """Verify make_gold_table returns a pandas DataFrame"""
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        result = make_gold_table(conn)
        
        assert isinstance(result, pd.DataFrame)


def test_make_gold_table_creates_composite_score(setup_silver_data):
    """Verify composite_score is calculated correctly"""
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        result = make_gold_table(conn)
        
        assert 'composite_score' in result.columns
        assert result['composite_score'].notna().all(), "All composite scores should be calculated"


def test_make_gold_table_applies_kev_multiplier():
    """Verify KEV entries get 1.5x multiplier"""
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        result = make_gold_table(conn)
        
        kev_entries = result[result['in_kev'] == 1]
        non_kev_entries = result[result['in_kev'] == 0]
        
        # KEV entries should have higher scores due to 1.5x multiplier
        for _, row in kev_entries.iterrows():
            expected_score = row['cvss_score'] * 1.5 * criticality_weight[row['gi_criticality']]
            assert abs(row['composite_score'] - expected_score) < 0.01, \
                f"KEV multiplier not applied correctly for {row['cve_id']}"


def test_make_gold_table_applies_criticality_weight():
    """Verify criticality weights are applied correctly"""
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        result = make_gold_table(conn)
        
        # Test each criticality level
        for criticality, weight in criticality_weight.items():
            entries = result[result['gi_criticality'] == criticality]
            if len(entries) > 0:
                for _, row in entries.iterrows():
                    expected_score = row['cvss_score'] * row['in_kev'].map({1: 1.5, 0: 1.0}) * weight
                    assert abs(row['composite_score'] - expected_score) < 0.01


def test_make_gold_table_handles_missing_cvss_score():
    """Verify missing CVSS scores default to 1"""
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        # Add entry with missing CVSS score
        conn.execute("""
            INSERT INTO silver_nvd_kev 
            (cve_id, gi_software_name, gi_vendor, gi_criticality, approved_version, 
             cvss_score, in_kev) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, ('CVE-2023-9999', 'Test Software', 'Test Vendor', 'High', '1.0', None, 0))
        
        result = make_gold_table(conn)
        
        # Should use 1.0 as default for missing CVSS
        test_entry = result[result['cve_id'] == 'CVE-2023-9999']
        expected_score = 1.0 * 1.0 * criticality_weight['High']  # cvss_score=1, in_kev=0, weight=High
        assert abs(test_entry['composite_score'].iloc[0] - expected_score) < 0.01


def test_make_gold_table_drops_duplicates():
    """Verify duplicate CVE/software combinations are removed"""
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        result = make_gold_table(conn)
        
        # Should have 3 unique CVE/software combinations
        # (CVE-2023-1234 appears twice but with same software)
        assert len(result) == 3


def test_make_gold_table_has_expected_columns():
    """Verify gold table has the expected schema"""
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        result = make_gold_table(conn)
        
        expected_columns = [
            'cve_id', 'gi_software_name', 'gi_vendor', 
            'cvss_score', 'in_kev', 'composite_score'
        ]
        assert all(col in result.columns for col in expected_columns)


def test_save_creates_gold_table(setup_silver_data):
    """Verify save function creates gold table"""
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        result = make_gold_table(conn)
        save(result, conn)
    
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='gold_nvd_kev'")
    assert cursor.fetchone() is not None


def test_save_data_integrity(setup_silver_data):
    """Verify saved gold table has correct data"""
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        result = make_gold_table(conn)
        save(result, conn)
        
        saved_df = pd.read_sql("SELECT * FROM gold_nvd_kev", conn)
        
        assert len(saved_df) == len(result)
        assert set(saved_df['cve_id']) == set(result['cve_id'])


def test_make_gold_table_composite_score_rounding():
    """Verify composite scores are rounded to 3 decimal places"""
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        result = make_gold_table(conn)
        
        for score in result['composite_score']:
            # Check if score has at most 3 decimal places
            score_str = str(score)
            if '.' in score_str:
                decimal_places = len(score_str.split('.')[1])
                assert decimal_places <= 3, f"Score {score} has more than 3 decimal places"


def test_make_gold_table_handles_empty_silver_data():
    """Verify graceful handling when silver table is empty"""
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        # Clear silver table
        conn.execute("DELETE FROM silver_nvd_kev")
        
        result = make_gold_table(conn)
        
        assert isinstance(result, pd.DataFrame)
        assert len(result) == 0


def test_make_gold_table_criticality_weight_values():
    """Verify criticality weights are correctly defined"""
    expected_weights = {"Critical": 1.2, "High": 1, "Medium": 0.7, "Low": 0.3}
    assert criticality_weight == expected_weights


def test_make_gold_table_kev_multiplier_values():
    """Verify KEV multiplier mapping is correct"""
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        result = make_gold_table(conn)
        
        # Test that in_kev=1 gives 1.5x multiplier
        kev_multiplier = result[result['in_kev'] == 1]['composite_score'].iloc[0] / \
                        result[result['in_kev'] == 1]['cvss_score'].iloc[0]
        assert abs(kev_multiplier - 1.5) < 0.01


def test_make_gold_table_preserves_software_context():
    """Verify software and vendor information is preserved"""
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        result = make_gold_table(conn)
        
        # Check that software context is preserved
        windows_entries = result[result['gi_software_name'] == 'Windows 11 Enterprise']
        assert len(windows_entries) == 1  # Duplicates removed
        assert windows_entries['gi_vendor'].iloc[0] == 'Microsoft'
        assert windows_entries['gi_criticality'].iloc[0] == 'Critical'


def test_make_gold_table_score_calculation_example():
    """Verify specific score calculation example"""
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        result = make_gold_table(conn)
        
        # CVE-2023-1234: cvss=9.8, in_kev=1, criticality=Critical (weight=1.2)
        # Expected: 9.8 * 1.5 * 1.2 = 17.64
        cve_entry = result[result['cve_id'] == 'CVE-2023-1234']
        expected_score = 9.8 * 1.5 * 1.2
        assert abs(cve_entry['composite_score'].iloc[0] - expected_score) < 0.01
        
        # CVE-2023-5678: cvss=7.5, in_kev=0, criticality=Critical (weight=1.2)
        # Expected: 7.5 * 1.0 * 1.2 = 9.0
        cve_entry = result[result['cve_id'] == 'CVE-2023-5678']
        expected_score = 7.5 * 1.0 * 1.2
        assert abs(cve_entry['composite_score'].iloc[0] - expected_score) < 0.01