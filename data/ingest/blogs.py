import sqlite3
import feedparser
import pandas as pd
from pathlib import Path
from bs4 import BeautifulSoup


#using RSS to scrape xml from blogs - web scraping blocked on some sites

DB_PATH = Path('data/corpus.db')

#Setting this variable as number of days in past to look for blogs 
# TODO take this setting out of individual files (set accross search)

DAYS_BACK = 20

#All blogs to check - Can add more here or remove
BLOG_SOURCES = [
    {'name': 'Microsoft Security Blog', 'url': 'https://www.microsoft.com/en-us/security/blog/feed/'},
    {'name': 'Cisco Talos',             'url': 'https://blog.talosintelligence.com/rss'},
    {'name': 'Krebs on Security',       'url': 'https://krebsonsecurity.com/feed/'},
    {'name': 'Google Project Zero',     'url': 'http://googleprojectzero.blogspot.com/feeds/posts/default'},
    {'name': 'Bleeping Computer',       'url': 'https://www.bleepingcomputer.com/feed/'},
    {'name': 'Dark Reading',            'url': 'https://www.darkreading.com/rss.xml'},
    {'name': 'VulnCheck',               'url': 'https://www.vulncheck.com/blog/rss.xml'},
    {'name': 'Google Bug Hunters',      'url': 'https://bughunters.google.com/blog/rss'},
    {'name': 'CERT',                    'url': 'https://www.kb.cert.org/vulfeed'}
]

def get_entry_date(entry):
    """
    Extract publication date from RSS or Atom feed entry.
    """
    for field in (
        "published_parsed",
        "updated_parsed",
        "created_parsed",
    ):
        if field in entry and entry[field]:
            return pd.Timestamp(*entry[field][:6])

    return None


def get_blogs(days_back=DAYS_BACK):
    cutoff = pd.Timestamp.today() - pd.Timedelta(days=days_back)
    all_rows = []

    for source in BLOG_SOURCES:

        feed = feedparser.parse(source['url'])

        for blog in feed.entries:

            pub_date = get_entry_date(blog)
            if pub_date < cutoff:
                continue

            raw_html = (
                blog.get('content', [{}])[0].get('value', '')
                or blog.get('summary', '')
            )

            clean_text = BeautifulSoup(raw_html,'html.parser').get_text(
                separator=' ',strip=True)

            all_rows.append({
                'source': source['name'],
                'date': str(pub_date.date()),
                'title': blog.get('title', ''),
                'url': blog.get('link', ''),
                'content': clean_text,
            })

    return pd.DataFrame(all_rows)


def store_blogs(df: pd.DataFrame):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS blogs (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                source  TEXT,
                date    TEXT,
                title   TEXT,
                url     TEXT UNIQUE,
                content TEXT
            )
        ''')
        #Insert or ignore so reruns don't duplicate posts
        for _, row in df.iterrows():
            conn.execute('''
                INSERT OR IGNORE INTO blogs (source, date, title, url, content)
                VALUES (?, ?, ?, ?, ?)
            ''', (row['source'], row['date'], row['title'], row['url'], row['content']))

if __name__ == '__main__':
    store_blogs(get_blogs())
