import pytest
import pandas as pd
from unittest.mock import Mock, patch
import sqlite3
import json
from pathlib import Path

from src.ingestion.blogs import get_blogs, store_blogs, get_entry_date, BLOG_SOURCES

DATA_DIR = Path(__file__).parent.parent / "data"

def load_feed_entries():
    """Load blog entry data from JSON file"""
    with open(DATA_DIR / "mock_blogs.json", "r") as f:
        return json.load(f)["blog_entries"]

def test_get_entry_date_extract_published():
    """Verify get_entry_date extracts published_parsed correctly"""
    entries = load_feed_entries()
    entry = entries[0]  # Use first entry from file
    
    result = get_entry_date(entry)
    assert result.year == 2023
    assert result.month == 11
    assert result.day == 15

def test_get_entry_date_falls_back_to_updated():
    """Verify get_entry_date falls back to updated_parsed when published_parsed missing"""
    entries = load_feed_entries()
    entry = entries[2]  # Entry with only published_parsed and updated_parsed
    
    result = get_entry_date(entry)
    assert result.year == 2023
    assert result.month == 11
    assert result.day == 18

def test_get_entry_date_falls_back_to_created():
    """Verify get_entry_date falls back to created_parsed when other fields missing"""
    entries = load_feed_entries()
    # Find entry with created_parsed only (no published_parsed or updated_parsed)
    entry = next(
        (e for e in entries if 'created_parsed' in e and 'published_parsed' not in e and 'updated_parsed' not in e),
        None
    )
    assert entry is not None, "No entry with created_parsed only found in mock_blogs.json"
    
    result = get_entry_date(entry)
    assert result.year == 2023
    assert result.month == 11
    assert result.day == 17

def test_get_entry_date_returns_none_when_no_dates():
    """Verify get_entry_date returns None when no date fields present"""
    entry = {'title': 'Test Blog', 'link': 'http://example.com'}
    
    result = get_entry_date(entry)
    assert result is None