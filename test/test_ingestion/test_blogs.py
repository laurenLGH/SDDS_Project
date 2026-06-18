import pytest
import pandas as pd
from unittest.mock import Mock, patch
import sqlite3

from src.ingestion.blogs import get_blogs, store_blogs, get_entry_date, BLOG_SOURCES

MOCK_BLOG_ENTRIES = [
    {
        'title': 'Microsoft Security Update November',
        'link': 'https://www.microsoft.com/en-us/security/blog/2023/11/15/microsoft-security-update/',
        'published_parsed': (2023, 11, 15, 10, 0, 0, 0, 0, 0),
        'summary': '<p>Microsoft releases critical security updates for Windows and Office.</p>',
        'content': [{'value': '<div><p>Microsoft releases critical security updates for Windows and Office.</p></div>'}]
    },
    {
        'title': 'CVE-2023-1234 Analysis',
        'link': 'https://blog.talosintelligence.com/2023/11/cve-2023-1234/',
        'published_parsed': (2023, 11, 16, 14, 30, 0, 0, 0, 0),
        'summary': 'Detailed analysis of the recent Windows vulnerability.',
        'content': [{'value': '<div><p>Detailed analysis of the recent Windows vulnerability.</p></div>'}]
    },
    {
        'title': 'Krebs Report on Cybercrime',
        'link': 'https://krebsonsecurity.com/2023/11/cybercrime-report/',
        'published_parsed': (2023, 11, 18, 9, 0, 0, 0, 0, 0),
        'summary': 'Investigation into recent cybercrime trends.',
        'content': [{'value': '<div><p>Investigation into recent cybercrime trends.</p></div>'}]
    }
]


def test_get_entry_date_extract_published():
    """Verify get_entry_date extracts published_parsed correctly"""
    entry = {
        'published_parsed': (2023, 11, 15, 10, 0, 0, 0, 0, 0),
        'updated_parsed': (2023, 11, 16, 14, 30, 0, 0, 0, 0)
    }
    
    result = get_entry_date(entry)
    assert result.year == 2023
    assert result.month == 11
    assert result.day == 15


def test_get_entry_date_falls_back_to_updated():
    """Verify get_entry_date falls back to updated_parsed when published_parsed missing"""
    entry = {
        'updated_parsed': (2023, 11, 16, 14, 30, 0, 0, 0, 0)
    }
    
    result = get_entry_date(entry)
    assert result.year == 2023
    assert result.month == 11
    assert result.day == 16


def test_get_entry_date_falls_back_to_created():
    """Verify get_entry_date falls back to created_parsed when other fields missing"""
    entry = {
        'created_parsed': (2023, 11, 17, 8, 0, 0, 0, 0, 0)
    }
    
    result = get_entry_date(entry)
    assert result.year == 2023
    assert result.month == 11
    assert result.day == 17


def test_get_entry_date_returns_none_when_no_dates():
    """Verify get_entry_date returns None when no date fields present"""
    entry = {'title': 'Test Blog', 'link': 'http://example.com'}
    
    result = get_entry_date(entry)
    assert result is None


def test_get_blogs_returns_dataframe():
    """Verify get_blogs returns a pandas DataFrame"""
    with patch('src.ingestion.blogs.feedparser.parse') as mock_parse:
        mock_feed = Mock()
        mock_feed.entries = MOCK_BLOG_ENTRIES
        mock_parse.return_value = mock_feed
        
        df = get_blogs(days_back=30)
        
        assert isinstance(df, pd.DataFrame)


def test_get_blogs_has_expected_columns():
    """Verify blogs DataFrame has the expected schema"""
    with patch('src.ingestion.blogs.feedparser.parse') as mock_parse:
        mock_feed = Mock()
        mock_feed.entries = MOCK_BLOG_ENTRIES
        mock_parse.return_value = mock_feed
        
        df = get_blogs(days_back=30)
        
        expected_columns = ['source', 'date', 'title', 'url', 'content']
        assert all(col in df.columns for col in expected_columns)


def test_get_blogs_filters_by_date():
    """Verify blogs are filtered by date cutoff"""
    recent_entry = {
        'title': 'Recent Blog Post',
        'link': 'https://example.com/recent',
        'published_parsed': (2023, 11, 20, 10, 0, 0, 0, 0, 0),
        'summary': 'Recent post',
        'content': [{'value': '<div>Recent post</div>'}]
    }
    
    old_entry = {
        'title': 'Old Blog Post',
        'link': 'https://example.com/old',
        'published_parsed': (2023, 10, 1, 10, 0, 0, 0, 0, 0),
        'summary': 'Old post',
        'content': [{'value': '<div>Old post</div>'}]
    }
    
    with patch('src.ingestion.blogs.feedparser.parse') as mock_parse:
        mock_feed = Mock()
        mock_feed.entries = [recent_entry, old_entry]
        mock_parse.return_value = mock_feed
        
        df = get_blogs(days_back=30)  # Should exclude old_entry
        
        assert len(df) == 1, "Should only include recent blog"
        assert df['title'].iloc[0] == 'Recent Blog Post'


def test_get_blogs_extract_content_from_content_field():
    """Verify content is extracted from content field when available"""
    entry_with_content = {
        'title': 'Blog with Content',
        'link': 'https://example.com/content',
        'published_parsed': (2023, 11, 15, 10, 0, 0, 0, 0, 0),
        'content': [{'value': '<div><p>Full content here</p></div>'}],
        'summary': 'Summary text'
    }
    
    with patch('src.ingestion.blogs.feedparser.parse') as mock_parse:
        mock_feed = Mock()
        mock_feed.entries = [entry_with_content]
        mock_parse.return_value = mock_feed
        
        df = get_blogs(days_back=30)
        
        assert 'Full content here' in df['content'].iloc[0]
        assert 'Summary text' not in df['content'].iloc[0]


def test_get_blogs_falls_back_to_summary():
    """Verify content falls back to summary when content field missing"""
    entry_with_summary = {
        'title': 'Blog with Summary',
        'link': 'https://example.com/summary',
        'published_parsed': (2023, 11, 15, 10, 0, 0, 0, 0, 0),
        'summary': '<p>Summary content here</p>'
    }
    
    with patch('src.ingestion.blogs.feedparser.parse') as mock_parse:
        mock_feed = Mock()
        mock_feed.entries = [entry_with_summary]
        mock_parse.return_value = mock_feed
        
        df = get_blogs(days_back=30)
        
        assert 'Summary content here' in df['content'].iloc[0]


def test_get_blogs_strips_html_tags():
    """Verify HTML tags are stripped from content"""
    entry_with_html = {
        'title': 'Blog with HTML',
        'link': 'https://example.com/html',
        'published_parsed': (2023, 11, 15, 10, 0, 0, 0, 0, 0),
        'content': [{'value': '<div><p>Content with <strong>HTML</strong> tags</p></div>'}]
    }
    
    with patch('src.ingestion.blogs.feedparser.parse') as mock_parse:
        mock_feed = Mock()
        mock_feed.entries = [entry_with_html]
        mock_parse.return_value = mock_feed
        
        df = get_blogs(days_back=30)
        
        assert 'Content with HTML tags' in df['content'].iloc[0]
        assert '<strong>' not in df['content'].iloc[0]


def test_store_blogs_creates_table(test_db_connection):
    """Verify store_blogs creates the database table"""
    df = pd.DataFrame({
        'source': ['Test Source'],
        'date': ['2023-11-15'],
        'title': ['Test Title'],
        'url': ['https://example.com/test'],
        'content': ['Test content']
    })
    
    store_blogs(df)
    
    cursor = test_db_connection.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='blogs'")
    assert cursor.fetchone() is not None


def test_store_blogs_has_correct_schema():
    """Verify blogs table has the expected schema"""
    df = pd.DataFrame({
        'source': ['Test Source'],
        'date': ['2023-11-15'],
        'title': ['Test Title'],
        'url': ['https://example.com/test'],
        'content': ['Test content']
    })
    
    store_blogs(df)
    
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(blogs)")
        columns = {row[1] for row in cursor.fetchall()}
        
        expected_columns = {'id', 'source', 'date', 'title', 'url', 'content'}
        assert columns == expected_columns, f"Schema mismatch: {columns ^ expected_columns}"


def test_store_blogs_prevents_duplicates():
    """Verify store_blogs doesn't duplicate entries with same URL"""
    df = pd.DataFrame({
        'source': ['Test Source'],
        'date': ['2023-11-15'],
        'title': ['Test Title'],
        'url': ['https://example.com/test'],
        'content': ['Test content']
    })
    
    store_blogs(df)
    store_blogs(df)  # Try to insert again
    
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        result_df = pd.read_sql("SELECT * FROM blogs", conn)
        assert len(result_df) == 1, "Should not duplicate entries"


def test_store_blogs_handles_multiple_sources():
    """Verify store_blogs handles multiple blog sources"""
    df = pd.DataFrame({
        'source': ['Microsoft Security Blog', 'Cisco Talos', 'Krebs on Security'],
        'date': ['2023-11-15', '2023-11-16', '2023-11-17'],
        'title': ['Post 1', 'Post 2', 'Post 3'],
        'url': ['https://microsoft.com/1', 'https://talos.com/2', 'https://krebsonsecurity.com/3'],
        'content': ['Content 1', 'Content 2', 'Content 3']
    })
    
    store_blogs(df)
    
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        result_df = pd.read_sql("SELECT * FROM blogs", conn)
        assert len(result_df) == 3
        assert set(result_df['source']) == {'Microsoft Security Blog', 'Cisco Talos', 'Krebs on Security'}


def test_store_blogs_date_format():
    """Verify dates are stored in YYYY-MM-DD format"""
    df = pd.DataFrame({
        'source': ['Test Source'],
        'date': ['2023-11-15'],
        'title': ['Test Title'],
        'url': ['https://example.com/test'],
        'content': ['Test content']
    })
    
    store_blogs(df)
    
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        result_df = pd.read_sql("SELECT * FROM blogs", conn)
        assert len(result_df['date'].iloc[0]) == 10
        assert result_df['date'].iloc[0][4] == '-'


def test_get_blogs_handles_empty_feed():
    """Verify get_blogs handles empty feed gracefully"""
    with patch('src.ingestion.blogs.feedparser.parse') as mock_parse:
        mock_feed = Mock()
        mock_feed.entries = []
        mock_parse.return_value = mock_feed
        
        df = get_blogs(days_back=30)
        
        assert isinstance(df, pd.DataFrame)
        assert len(df) == 0


def test_get_blogs_handles_missing_fields():
    """Verify get_blogs handles missing feed entry fields"""
    entry_missing_fields = {
        'link': 'https://example.com',
        'published_parsed': (2023, 11, 15, 10, 0, 0, 0, 0, 0),
        'summary': 'Summary only'
        # Missing title, content
    }
    
    with patch('src.ingestion.blogs.feedparser.parse') as mock_parse:
        mock_feed = Mock()
        mock_feed.entries = [entry_missing_fields]
        mock_parse.return_value = mock_feed
        
        df = get_blogs(days_back=30)
        
        assert len(df) == 1
        assert df['title'].iloc[0] == ''  # Should default to empty string


def test_store_blogs_url_uniqueness_constraint():
    """Verify URL uniqueness constraint prevents duplicates"""
    df1 = pd.DataFrame({
        'source': ['Source A'],
        'date': ['2023-11-15'],
        'title': ['First Title'],
        'url': ['https://example.com/same-url'],
        'content': ['First content']
    })
    
    df2 = pd.DataFrame({
        'source': ['Source B'],
        'date': ['2023-11-16'],
        'title': ['Second Title'],
        'url': ['https://example.com/same-url'],  # Same URL
        'content': ['Second content']
    })
    
    store_blogs(df1)
    store_blogs(df2)
    
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        result_df = pd.read_sql("SELECT * FROM blogs", conn)
        assert len(result_df) == 1, "Should only have one entry with same URL"
        assert result_df['title'].iloc[0] == 'First Title'  # First entry preserved


def test_store_blogs_data_integrity():
    """Verify data integrity after storage"""
    df = pd.DataFrame({
        'source': ['Test Source'],
        'date': ['2023-11-15'],
        'title': ['Test Title'],
        'url': ['https://example.com/test'],
        'content': ['Test content']
    })
    
    store_blogs(df)
    
    with sqlite3.connect('test/data/test_corpus.db') as conn:
        result_df = pd.read_sql("SELECT * FROM blogs", conn)
        
        assert len(result_df) == len(df)
        assert result_df['source'].iloc[0] == 'Test Source'
        assert result_df['title'].iloc[0] == 'Test Title'
        assert result_df['url'].iloc[0] == 'https://example.com/test'
        assert result_df['content'].iloc[0] == 'Test content'