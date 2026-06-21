# Testing Guide

This directory contains the test suite for the vulnerability intelligence pipeline application.

## Test Framework

We use **pytest** as our testing framework. Run tests with:

```bash
pytest
pytest -v  # Verbose output
pytest test/test_processing/  # Run specific test directory
pytest test/test_processing/test_make_gold.py::test_make_gold_table_returns_dataframe  # Run specific test
```

## Test Structure

### Test Files

- `test_processing/` - Tests for data processing pipelines
  - `test_make_silver.py` - Tests for NVD/KEV data processing and enrichment
  - `test_make_gold.py` - Tests for gold table generation with scoring

### Test Data

Test data is stored in `test/data/`:
- `mock_nvd.json` - Mock NVD CVE data
- `mock_kev.json` - Mock KEV vulnerability data  
- `mock_blogs.json` - Mock blog feed data
- `golden_image.csv` - Golden image data for testing

## Test Configuration

### Database Setup

Tests use a temporary SQLite database located at `test/data/test_corpus.db`. The database is automatically cleaned up before and after each test run.

### Fixtures

- `setup_silver_data()` - Sets up test database with silver data for make_gold tests
- `setup_test_env()` - Handles test database cleanup (defined in `conftest.py`)

## Writing Tests

### General Guidelines

1. **Use descriptive test names** that clearly indicate what is being tested
2. **Test one thing per test** - keep tests focused and specific
3. **Use parameterized tests** for similar scenarios with different inputs
4. **Test edge cases** like empty data, missing values, and error conditions
5. **Verify data integrity** - check row counts, schemas, and data types

### Test Patterns

#### Database Tests

```python
def test_database_operation():
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        # Test database operations
        result = pd.read_sql("SELECT * FROM table_name", conn)
        assert len(result) > 0
```

#### DataFrame Tests

```python
def test_dataframe_operations():
    df = fetch_golden_image()
    assert isinstance(df, pd.DataFrame)
    assert len(df) > 0
    assert 'expected_column' in df.columns
```

#### Data Processing Tests

```python
def test_data_processing():
    # Setup test data
    # Process data
    # Verify results
    assert result is not None
    assert len(result) > 0
```

## Test Data Management

### Creating Test Data

1. Use the mock JSON files in `test/data/` for structured data
2. Create CSV files for tabular data that matches your schema
3. Ensure test data covers various scenarios (normal, edge cases, error conditions)

### Data Consistency

- Tests should be independent and not rely on data from other tests
- Use fixtures to set up consistent test data
- Clean up test data after tests complete

## CI/CD Integration

Tests are run automatically in CI/CD pipelines. Ensure all tests pass before merging:

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test suite
pytest test/test_processing/
```

## Debugging Tests

### Common Issues

1. **Database errors** - Ensure `test_corpus.db` exists and has required tables
2. **Path issues** - Use relative paths from the test directory
3. **Data type mismatches** - Verify data types match expected schemas

### Debugging Tips

```bash
# Run with more verbose output
pytest -v -s

# Stop on first failure
pytest -x

# Run with pdb for debugging
pytest --pdb
```

## Best Practices

1. **Test the interface, not the implementation** - Test what the function does, not how it does it
2. **Use meaningful assertions** - Check specific values and conditions, not just that results exist
3. **Keep tests fast** - Avoid unnecessary I/O operations
4. **Document test purpose** - Use docstrings to explain what each test verifies
5. **Test error handling** - Verify graceful handling of edge cases and errors

## Current Test Coverage

- Data fetching and validation
- Data processing pipelines
- Database operations
- Score calculations and multipliers
- Duplicate handling
- Schema validation
- Edge cases and error handling

## Future Test Improvements

- Add integration tests for end-to-end workflows
- Add tests for the make_gold.py and make_silver.py scripts. 
- Add performance benchmarks for large datasets
- Add security tests for data validation
- Add tests for API endpoints (if applicable)