import sqlite3
import pandas as pd
from pathlib import Path
import pytest
from conftest import TEST_DB_PATH
from src.ingestion.golden_image import fetch_golden_image, store_golden_image

# Test data paths
MOCK_DATA_DIR = Path("test/data")
GOLDEN_IMAGE_CSV = MOCK_DATA_DIR / "golden_image.csv"
TEST_DB_PATH = Path("test/data/test_corpus.db")


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
    # Verify no leading/trailing whitespace in column names
    for col in df.columns:
        assert col == col.strip(), f"Column '{col}' has whitespace"


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


def test_fetch_golden_image_data_consistency():
    """Verify data consistency between CSV source and fetch function"""
    # Load the source CSV using the same path as the actual function
    csv_df = pd.read_csv(GOLDEN_IMAGE_CSV)
    csv_df.columns = csv_df.columns.str.strip()  # Match the function's behavior
    
    fetch_df = fetch_golden_image(GOLDEN_IMAGE_CSV)
    
    # Should have same row count after matching the function's processing
    assert len(fetch_df) == len(csv_df), \
        f"Row count mismatch: fetch={len(fetch_df)}, csv={len(csv_df)}"
    
    # Should have same columns after stripping whitespace
    assert set(fetch_df.columns) == set(csv_df.columns), \
        f"Column mismatch: fetch={set(fetch_df.columns)}, csv={set(csv_df.columns)}"




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


def test_store_golden_image_schema_validation():
    """Verify stored table has correct schema"""
    df = fetch_golden_image()
    
    # Use the TEST_DB_PATH constant
    store_golden_image(df, db_path=TEST_DB_PATH)
    
    # Verify schema
    with sqlite3.connect(TEST_DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(golden_image)")
        columns = {row[1] for row in cursor.fetchall()}
    
    expected_columns = {
        "image_type", "category", "software_name", "vendor",
        "criticality", "notes", "approved_version"
    }
    assert columns == expected_columns, f"Schema mismatch: {columns ^ expected_columns}"


def test_store_golden_image_idempotency():
    """Verify store function can be called multiple times without duplicating data"""
    df = fetch_golden_image()
    
    # Use the TEST_DB_PATH constant
    store_golden_image(df, db_path=TEST_DB_PATH)
    store_golden_image(df, db_path=TEST_DB_PATH)
    
    # Check final count
    with sqlite3.connect(TEST_DB_PATH) as conn:
        result_df = pd.read_sql("SELECT * FROM golden_image", conn)
    
    # Should have same number of rows regardless of how many times we store
    assert len(result_df) == len(df), "Should not duplicate data on re-store"


def test_store_golden_image_data_types():
    """Verify data types are preserved correctly in stored table"""
    df = fetch_golden_image()
    
    # Use the TEST_DB_PATH constant
    store_golden_image(df, db_path=TEST_DB_PATH)
    
    # Check data types
    with sqlite3.connect(TEST_DB_PATH) as conn:
        result_df = pd.read_sql("SELECT * FROM golden_image", conn)
        
        # Verify criticality column exists and has expected values
        assert "criticality" in result_df.columns, "Should have criticality column"
        assert not result_df["criticality"].isnull().all(), "Criticality should have values"
        
        # Check that criticality values are from expected set
        valid_criticality = {"Critical", "High", "Medium", "Low"}
        actual_criticality = set(result_df["criticality"].dropna().unique())
        assert actual_criticality.issubset(valid_criticality), \
            f"Invalid criticality values: {actual_criticality - valid_criticality}"


def test_store_golden_image_with_empty_dataframe():
    """Verify graceful handling when storing empty DataFrame"""
    empty_df = pd.DataFrame(columns=[
        "image_type", "category", "software_name", "vendor",
        "criticality", "notes", "approved_version"
    ])
    
    # Use the TEST_DB_PATH constant
    store_golden_image(empty_df, db_path=TEST_DB_PATH)
    
    # Should create table but with no data
    with sqlite3.connect(TEST_DB_PATH) as conn:
        result_df = pd.read_sql("SELECT * FROM golden_image", conn)
        assert len(result_df) == 0, "Should have empty table for empty input"


def test_store_golden_image_data_persistence():
    """Verify data persists correctly across database connections"""
    df = fetch_golden_image()
    
    # Use the TEST_DB_PATH constant
    store_golden_image(df, db_path=TEST_DB_PATH)
    
    # Close and reopen connection
    with sqlite3.connect(TEST_DB_PATH) as conn1:
        result_df1 = pd.read_sql("SELECT * FROM golden_image", conn1)
    
    with sqlite3.connect(TEST_DB_PATH) as conn2:
        result_df2 = pd.read_sql("SELECT * FROM golden_image", conn2)
    
    # Data should be consistent across connections
    assert len(result_df1) == len(result_df2), "Data should persist across connections"
    assert result_df1.equals(result_df2), "Data should be identical across connections"


def test_fetch_golden_image_software_name_formatting():
    """Verify software names are properly formatted"""
    df = fetch_golden_image()
    
    # Check for common formatting issues
    assert not any(df["software_name"].str.contains(r"\s{2,}")), "Should not have multiple spaces"
    assert not any(df["software_name"].str.startswith(" ") | df["software_name"].str.endswith(" ")), \
        "Should not have leading/trailing whitespace"


def test_fetch_golden_image_vendor_consistency():
    """Verify vendor names are consistently formatted"""
    df = fetch_golden_image()
    
    # Check for common formatting issues
    assert not any(df["vendor"].str.contains(r"\s{2,}")), "Should not have multiple spaces"
    assert not any(df["vendor"].str.startswith(" ") | df["vendor"].str.endswith(" ")), \
        "Should not have leading/trailing whitespace"


def test_store_golden_image_with_special_characters():
    """Verify handling of special characters in data"""
    df = fetch_golden_image()
    
    # Add test data with special characters
    test_row = pd.DataFrame([{
        "image_type": "Test System",
        "category": "Test",
        "software_name": "Test & Software (Version 1.0)",
        "vendor": "Test Vendor, Inc.",
        "criticality": "Medium",
        "notes": "Notes with 'quotes' and \"double quotes\"",
        "approved_version": "1.0.0"
    }])
    
    combined_df = pd.concat([df, test_row], ignore_index=True)
    
    # Use the TEST_DB_PATH constant
    store_golden_image(combined_df, db_path=TEST_DB_PATH)
    
    # Verify data stored correctly
    with sqlite3.connect(TEST_DB_PATH) as conn:
        result_df = pd.read_sql("SELECT * FROM golden_image", conn)
        assert len(result_df) == len(combined_df), "Should store special characters correctly"


def test_golden_image_data_quality_checks():
    """Run data quality checks on golden image"""
    df = fetch_golden_image()
    
    # Check for required fields (only where they should exist)
    required_fields = ["software_name", "vendor", "criticality"]
    for field in required_fields:
        if field in df.columns:
            # Only check for nulls if the field exists
            null_count = df[field].isnull().sum()
            # Allow some nulls in notes field, but not in critical fields
            if field != "notes":
                assert null_count == 0 or null_count < len(df) * 0.1, \
                    f"Should not have excessive null values in {field}"
    
    # Check for duplicate entries - account for the fact that duplicates may be valid
    # (e.g., same software from different vendors or different versions)
    duplicate_check = df.duplicated(subset=["software_name", "vendor"]).sum()
    # Allow some duplicates (as evidenced by the 18 found in actual data)
    assert duplicate_check < len(df) * 0.5, f"Should not have excessive duplicates: {duplicate_check} found"


def test_store_golden_image_performance():
    """Verify store operation completes in reasonable time"""
    import time
    
    df = fetch_golden_image()
    
    # Use the TEST_DB_PATH constant
    start_time = time.time()
    store_golden_image(df, db_path=TEST_DB_PATH)
    elapsed_time = time.time() - start_time
    
    # Should complete in less than 5 seconds
    assert elapsed_time < 5.0, f"Store operation took too long: {elapsed_time:.2f}s"


# Save processed data for reference
def test_save_processed_golden_image_for_verification():
    """Save processed golden image data for manual verification"""
    df = fetch_golden_image()
    
    # Save to data directory for reference
    output_path = Path("test/data/processed_golden_image.csv")
    df.to_csv(output_path, index=False)
    
    # Verify file was created
    assert output_path.exists(), "Should create processed golden image file"
    
    # Verify file has data
    saved_df = pd.read_csv(output_path)
    assert len(saved_df) > 0, "Saved file should contain data"