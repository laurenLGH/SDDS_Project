# Ingest Scripts

One script per data source. Each fetches its source, normalizes/cleans the data, and writes it to a table in  `corpus.db`.

## Scripts

### `golden_image.py`
- **File:** `data/golden_image.csv`
- **Notes:** This is the Golden Image for which we will be finding cyber threat data. This is an example of an input for overall final product. 

### `kev.py`
- **Source:** `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- **File:** `data/kev.py'
- **Notes:** This is CISA's catalog of Known Exploited Vulnerabilities. When ingesting this data, all CVEs (Common Vulnerabilities and Exposures) ever added to KEV since Nov 2021 are returned

### `nvd.py`
- **Source:** `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **Notes:** This is NIST's National Vulnerability Database. When running the ingestion file for this data, CVE data will be returned according to a time window relative to the current day. Set `DAYS_BACK` to control how many days into the past to pull CVE data.


### `blogs.py`
- **Source:** RSS feeds of Security Blogs (Microsoft Security Blog, Cisco Talos, Krebs on Security, Google Project Zero) Note: Planning to add more sources soon
- **Notes:** This will pull RSS feeds from listed security blogs. Set `DAYS_BACK` to control lookback window. Add new sources to `BLOG_SOURCES` list.

## Settings to adjust

| Script | Variable | Default | What it controls |
|--------|----------|---------|-----------------|
| `nvd.py` | `DAYS_BACK` | 10 | CVE lookback window |
| `blogs.py` | `DAYS_BACK` | 10 | Blog post lookback window |
| `blogs.py` | `BLOG_SOURCES` | 4 sources | Which blogs to pull |
