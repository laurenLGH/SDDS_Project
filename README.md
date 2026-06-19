# Vulnerability Intelligence Pipeline

A data pipeline that aggregates cyber threat intelligence from multiple sources, enriches vulnerability data, and generates actionable insights for security teams.

## Overview

This project pulls vulnerability data from:
- **NIST National Vulnerability Database (NVD)** - CVE details and CVSS scores
- **CISA Known Exploited Vulnerabilities (KEV)** - Actively exploited vulnerabilities
- **Security Blogs** - Threat intelligence and analysis from industry experts
- **Golden Image** - Your organization's software inventory

The pipeline processes this data through multiple stages:
1. **Ingestion** - Pull raw data from sources
2. **Silver Layer** - Enrich vulnerabilities with KEV context and scoring
3. **Gold Layer** - Generate prioritized vulnerability scores

## Quick Start

### Option 1: Automated Startup (Recommended)

Run the comprehensive startup script that handles everything:

```bash
python start_app.py
```

This script will:
- Check if the database exists, and run all ingestion scripts if needed
- Start the backend server on port 5001
- Start the frontend server on port 5000
- Monitor both services and handle graceful shutdown

### Option 2: Manual Setup

1. **Set up your environment**
   - Create virtual environment: `python -m venv .venv`
   - Activate: `source .venv/bin/activate` (Linux/Mac) or `.venv\Scripts\activate` (Windows)
   - Install dependencies: `pip install -r requirements.txt`

2. **Ingest data**
   ```bash
   python data/ingest/golden_image.py
   python data/ingest/kev.py
   python data/ingest/nvd.py
   python data/ingest/blogs.py
   python src/processing/make_silver.py
   python src/processing/make_gold.py
   ```

3. **Start servers**
   ```bash
   # Backend (port 5001)
   python src/models/main.py
   
   # Frontend (port 5000)
   flask --app src.main:app run --port 5000 --host 0.0.0.0
   ```

## Project Structure

```
├── data/              # SQLite database and ingest scripts
├── src/               # Processing pipelines and models
├── test/              # Test suite
├── SeeData.ipynb      # Jupyter notebook for data exploration
├── start_app.py       # Automated application startup script
└── requirements.txt   # Python dependencies
```

## Documentation

- **[Data README](data/README.md)** - Database schema and data sources
- **[Ingest Scripts README](src/ingestion/README.md)** - Data ingestion details
- **[Test README](test/README.md)** - Testing guide and patterns

## Data Exploration

### Using Jupyter Notebook

The `SeeData.ipynb` notebook provides an interactive way to explore your data:

1. **Environment Setup** (one-time):
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # or .venv\Scripts\activate on Windows
   pip install -r requirements.txt
   python -m ipykernel install --user --name=SDDS_Project
   ```

2. **Run Data Ingestion**:
   Execute the first cell in the notebook to pull data from all sources and create the database.

3. **Explore Data**:
   The notebook includes cells to display:
   - Golden Image data (your software inventory)
   - KEV data (known exploited vulnerabilities)
   - NVD data (CVE details and scores)
   - Silver and Gold processed data

   Modify the `lines_to_show` variable to control how many rows are displayed.

### Using start_app.py

The `start_app.py` script provides a one-command solution to get everything running:

```bash
python start_app.py
```

**What it does:**
- Checks for and creates the database if needed
- Runs all ingestion scripts automatically
- Starts the backend API server on port 5001
- Starts the frontend web interface on port 5000
- Monitors both processes and handles graceful shutdown

**Access the application:**
- Frontend: http://localhost:5000
- Backend API: http://localhost:5001

## Data Flow

```
Raw Sources → Ingestion → Silver Layer → Gold Layer → Insights
   (NVD, KEV,    (Clean,      (Enrich,      (Prioritize,
    Blogs,        Normalize)   Score,        Rank)
    Golden)
```

## Key Features

- **Automated Data Ingestion** - Pull latest vulnerability data daily
- **Contextual Enrichment** - Combine CVE data with KEV and blog intelligence
- **Prioritization Scoring** - Calculate risk scores based on CVSS, KEV status, and business criticality
- **Flexible Architecture** - Easy to add new data sources or processing steps
- **Interactive Data Exploration** - Jupyter notebook for analysis and visualization
- **Automated Deployment** - Single command to start the entire application

