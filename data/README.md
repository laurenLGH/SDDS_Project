# Data

Contains the SQLite database and ingest scripts for all vulnerability intelligence sources.

## Database

`corpus.db` — this database is created by running the data ingest files (pulling cyber threat intelligence data from each source)

| Table | Source | Description |
|-------|--------|-------------|
| `golden_image` | `SDDS_Project/golden_image.csv` | The golden image (example of an input for the tool) |
| `kev` | CISA KEV live feed | CISA Known exploited vulnerabilities |
| `nvd_cves` | NIST National Vulnerability Database | CVE detail and CVSS scores |
| `blogs` | RSS feeds | security blog posts |

## Usage

Run all ingest scripts to populate the database:

```bash
python data/ingest/golden_image.py
python data/ingest/kev.py
python data/ingest/nvd.py
python data/ingest/blogs.py
```
