import pytest
import pandas as pd
import sqlite3

from src.processing.make_gold import make_gold_table, save, criticality_weight, KEV_MULTIPLIER
from conftest import TEST_DB_PATH


@pytest.fixture(autouse=True)
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
            'date_published': ['2023-11-15', '2023-11-15', '2023-11-20', '2023-11-25'], 
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
        silver_df = pd.read_sql("SELECT * FROM silver_nvd_kev", conn)
        result = make_gold_table(silver_df)
        
        assert isinstance(result, pd.DataFrame)


def test_make_gold_table_creates_composite_score(setup_silver_data):
    """Verify composite_score is calculated correctly"""
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        silver_df = pd.read_sql("SELECT * FROM silver_nvd_kev", conn)
        result = make_gold_table(silver_df)
        
        assert 'composite_score' in result.columns
        assert result['composite_score'].notna().all(), "All composite scores should be calculated"


def test_make_gold_table_applies_kev_multiplier(setup_silver_data):
    """Verify KEV entries get 1.5x multiplier"""
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        silver_df = pd.read_sql("SELECT * FROM silver_nvd_kev", conn)
        result = make_gold_table(silver_df)
        
        kev_entries = result[result['in_kev'] == 1]
        non_kev_entries = result[result['in_kev'] == 0]
        
        # KEV entries should have higher scores due to 1.5x multiplier
        for _, row in kev_entries.iterrows():
            # Note: gi_criticality is not in the result DataFrame, so we need to get it from silver_df
            silver_entry = silver_df[(silver_df['cve_id'] == row['cve_id']) & 
                                    (silver_df['gi_software_name'] == row['gi_software_name'])].iloc[0]
            expected_score = row['cvss_score'] * 1.5 * criticality_weight[silver_entry['gi_criticality']]
            assert abs(row['composite_score'] - expected_score) < 0.01, \
                f"KEV multiplier not applied correctly for {row['cve_id']}"

def test_make_gold_table_applies_criticality_weight(setup_silver_data):
    """Verify criticality weights are applied correctly"""
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        silver_df = pd.read_sql("SELECT * FROM silver_nvd_kev", conn)
        result = make_gold_table(silver_df)
        
        # Test each criticality level
        for criticality, weight in criticality_weight.items():
            # Find entries in result that match this criticality
            for _, row in result.iterrows():
                # Get the corresponding silver entry to find the criticality
                silver_entry = silver_df[(silver_df['cve_id'] == row['cve_id']) & 
                                        (silver_df['gi_software_name'] == row['gi_software_name'])].iloc[0]
                if silver_entry['gi_criticality'] == criticality:
                    kev_mult = KEV_MULTIPLIER.get(row['in_kev'], 1.0)
                    expected_score = row['cvss_score'] * kev_mult * weight
                    assert abs(row['composite_score'] - expected_score) < 0.01


def test_make_gold_table_handles_missing_cvss_score(setup_silver_data):
    """Verify missing CVSS scores default to 1"""
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        # Add entry with missing CVSS score
        conn.execute("""
            INSERT INTO silver_nvd_kev 
            (cve_id, gi_software_name, gi_vendor, gi_criticality, approved_version, 
             cvss_score, in_kev) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, ('CVE-2023-9999', 'Test Software', 'Test Vendor', 'High', '1.0', None, 0))
        
        silver_df = pd.read_sql("SELECT * FROM silver_nvd_kev", conn)
        result = make_gold_table(silver_df)
        
        # Should use 1.0 as default for missing CVSS
        test_entry = result[result['cve_id'] == 'CVE-2023-9999']
        expected_score = 1.0 * 1.0 * criticality_weight['High']  # cvss_score=1, in_kev=0, weight=High
        assert abs(test_entry['composite_score'].iloc[0] - expected_score) < 0.01


def test_make_gold_table_drops_duplicates(setup_silver_data):
    """Verify duplicate CVE/software combinations are removed"""
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        silver_df = pd.read_sql("SELECT * FROM silver_nvd_kev", conn)
        result = make_gold_table(silver_df)
        
        # Should have 3 unique CVE/software combinations
        # (CVE-2023-1234 appears twice but with same software)
        assert len(result) == 3


def test_make_gold_table_has_expected_columns(setup_silver_data):
    """Verify gold table has the expected schema"""
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        silver_df = pd.read_sql("SELECT * FROM silver_nvd_kev", conn)
        result = make_gold_table(silver_df)
        
        expected_columns = [
            'cve_id', 'date_published', 'cve_description', 'gi_software_name', 
            'gi_vendor', 'cvss_score', 'in_kev', 'composite_score'
        ]
        assert all(col in result.columns for col in expected_columns)


def test_save_creates_gold_table(setup_silver_data):
    """Verify save function creates gold table"""
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        silver_df = pd.read_sql("SELECT * FROM silver_nvd_kev", conn)
        result = make_gold_table(silver_df)
        save(result, conn)
    
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='gold_nvd_kev'")
    assert cursor.fetchone() is not None


def test_save_data_integrity(setup_silver_data):
    """Verify saved gold table has correct data"""
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        silver_df = pd.read_sql("SELECT * FROM silver_nvd_kev", conn)
        result = make_gold_table(silver_df)
        save(result, conn)
        
        saved_df = pd.read_sql("SELECT * FROM gold_nvd_kev", conn)
        
        assert len(saved_df) == len(result)
        assert set(saved_df['cve_id']) == set(result['cve_id'])


def test_make_gold_table_composite_score_rounding(setup_silver_data):
    """Verify composite scores are rounded to 3 decimal places"""
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        silver_df = pd.read_sql("SELECT * FROM silver_nvd_kev", conn)
        result = make_gold_table(silver_df)
        
        for score in result['composite_score']:
            # Check if score has at most 3 decimal places
            score_str = str(score)
            if '.' in score_str:
                decimal_places = len(score_str.split('.')[1])
                assert decimal_places <= 3, f"Score {score} has more than 3 decimal places"


def test_make_gold_table_handles_empty_silver_data(setup_silver_data):
    """Verify graceful handling when silver table is empty"""
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        # Clear silver table
        conn.execute("DELETE FROM silver_nvd_kev")
        silver_df = pd.read_sql("SELECT * FROM silver_nvd_kev", conn)
        
        result = make_gold_table(silver_df)
        
        assert isinstance(result, pd.DataFrame)
        assert len(result) == 0


def test_make_gold_table_criticality_weight_values():
    """Verify criticality weights are correctly defined"""
    expected_weights = {"Critical": 1.2, "High": 1, "Medium": 0.7, "Low": 0.3}
    assert criticality_weight == expected_weights

def test_make_gold_table_kev_multiplier_values():
    """Verify KEV multiplier mapping is correct"""
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        silver_df = pd.read_sql("SELECT * FROM silver_nvd_kev", conn)
        result = make_gold_table(silver_df)
        
        # Test that in_kev=1 gives the correct multiplier
        kev_entries = result[result['in_kev'] == 1]
        non_kev_entries = result[result['in_kev'] == 0]
        
        if len(kev_entries) > 0 and len(non_kev_entries) > 0:
            # Get a KEV entry and a non-KEV entry with similar CVSS scores for comparison
            kev_entry = kev_entries.iloc[0]
            non_kev_entry = non_kev_entries.iloc[0]
            
            # Calculate the actual multiplier applied
            # The formula is: cvss_score * kev_multiplier * criticality_weight
            # So: composite_score = cvss_score * kev_multiplier * criticality_weight
            # Therefore: kev_multiplier = composite_score / (cvss_score * criticality_weight)
            
            # For KEV entry
            kev_criticality = silver_df[silver_df['cve_id'] == kev_entry['cve_id']].iloc[0]['gi_criticality']
            kev_expected_without_multiplier = kev_entry['cvss_score'] * criticality_weight[kev_criticality]
            kev_actual_multiplier = kev_entry['composite_score'] / kev_expected_without_multiplier
            
            # For non-KEV entry
            non_kev_criticality = silver_df[silver_df['cve_id'] == non_kev_entry['cve_id']].iloc[0]['gi_criticality']
            non_kev_expected_without_multiplier = non_kev_entry['cvss_score'] * criticality_weight[non_kev_criticality]
            non_kev_actual_multiplier = non_kev_entry['composite_score'] / non_kev_expected_without_multiplier
            
            # The KEV multiplier should be 1.5 and non-KEV should be 1.0
            assert abs(kev_actual_multiplier - 1.5) < 0.01, \
                f"KEV multiplier should be 1.5, got {kev_actual_multiplier}"
            assert abs(non_kev_actual_multiplier - 1.0) < 0.01, \
                f"Non-KEV multiplier should be 1.0, got {non_kev_actual_multiplier}"


def test_make_gold_table_preserves_software_context(setup_silver_data):
    """Verify software and vendor information is preserved"""
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        silver_df = pd.read_sql("SELECT * FROM silver_nvd_kev", conn)
        result = make_gold_table(silver_df)
        
        # Check that software context is preserved
        windows_entries = result[result['gi_software_name'] == 'Windows 11 Enterprise']
        assert len(windows_entries) == 1  # Duplicates removed
        assert windows_entries['gi_vendor'].iloc[0] == 'Microsoft'
        
        # Get the criticality from silver_df since it's not in the result
        silver_windows = silver_df[silver_df['cve_id'] == windows_entries['cve_id'].iloc[0]]
        assert len(silver_windows) > 0
        # Note: We can't directly check gi_criticality in result since it's not included
        # But we can verify the data flow worked correctly

def test_make_gold_table_score_calculation_example(setup_silver_data):
    """Verify specific score calculation example"""
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        silver_df = pd.read_sql("SELECT * FROM silver_nvd_kev", conn)
        result = make_gold_table(silver_df)
        
        # CVE-2023-1234: cvss=9.8, in_kev=1, criticality=Critical (weight=1.2)
        # Expected: 9.8 * 1.5 * 1.2 = 17.64
        cve_entry = result[result['cve_id'] == 'CVE-2023-1234']
        expected_score = 9.8 * 1.5 * 1.2
        assert abs(cve_entry['composite_score'].iloc[0] - expected_score) < 0.01, \
            f"Expected {expected_score}, got {cve_entry['composite_score'].iloc[0]}"
        
        # CVE-2023-5678: cvss=7.5, in_kev=0, criticality=Critical (weight=1.2)
        # Expected: 7.5 * 1.0 * 1.2 = 9.0
        cve_entry = result[result['cve_id'] == 'CVE-2023-5678']
        expected_score = 7.5 * 1.0 * 1.2
        assert abs(cve_entry['composite_score'].iloc[0] - expected_score) < 0.01, \
            f"Expected {expected_score}, got {cve_entry['composite_score'].iloc[0]}"
        
def test_make_gold_table_in_kev_mapping():
    """Verify in_kev column values are correctly mapped"""
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        silver_df = pd.read_sql("SELECT * FROM silver_nvd_kev", conn)
        result = make_gold_table(silver_df)
        
        # Check that in_kev values are preserved correctly
        assert set(result['in_kev'].unique()) == {0, 1}, "Should have both 0 and 1 values"
        
        # Verify the mapping logic
        for _, row in result.iterrows():
            if row['in_kev'] == 1:
                # Should have 1.5x multiplier applied
                silver_entry = silver_df[silver_df['cve_id'] == row['cve_id']].iloc[0]
                expected_score = row['cvss_score'] * 1.5 * criticality_weight[silver_entry['gi_criticality']]
                assert abs(row['composite_score'] - expected_score) < 0.01
            else:
                # Should have 1.0x multiplier applied
                silver_entry = silver_df[silver_df['cve_id'] == row['cve_id']].iloc[0]
                expected_score = row['cvss_score'] * 1.0 * criticality_weight[silver_entry['gi_criticality']]
                assert abs(row['composite_score'] - expected_score) < 0.01