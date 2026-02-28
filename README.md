# UCL Data Engineering Group Assignment

This project has been reorganized into a structure that better fits a standard data engineering workflow, with clear separation between ingestion, transformation, and analytics.

## Project Structure

```text
.
|-- data
|   |-- raw
|   |   |-- cisa_kev
|   |   |-- epss
|   |   `-- nvd
|   |-- staging
|   `-- curated
|-- docs
|-- notebooks
|-- sql
|   `-- postgres
`-- src
    |-- analytics
    |-- ingestion
    |   |-- cisa_kev
    |   `-- nvd
    `-- transformation
```

## Recommended Workflow

1. `data/raw`
   Store raw API/feed landing files without changing source fields.

2. `data/staging`
   Store cleaned intermediate datasets that are ready for joins, such as normalized NVD JSONL/CSV.

3. `data/curated`
   Store analytics-ready datasets, such as the vulnerability mart created by combining NVD, CISA KEV, and EPSS.

4. `src/ingestion`
   Store data ingestion scripts.

5. `src/transformation`
   Store data cleaning, join, and feature engineering scripts.

6. `src/analytics`
   Store DuckDB/SQL queries, notebook logic, or analytics documentation.

7. `sql/postgres`
   Store PostgreSQL schema, table, and index creation scripts.

## Current Datasets

- `data/raw/nvd/nvdcve-2.0-2026.json`
- `data/raw/cisa_kev/cisa_kev_catalog.json`
- `data/raw/cisa_kev/cisa_kev_catalog.csv`
- `data/raw/epss/epss_scores.json`

## How To Run

Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

Fetch the latest NVD data:

```bash
python3 src/ingestion/nvd/ingest_nvd.py --days 30
```

Fetch the latest CISA KEV data:

```bash
python3 src/ingestion/cisa_kev/fetch_cisa_kev.py
```

Build the curated analytics dataset:

```bash
python3 src/transformation/build_vulnerability_mart.py
```

Start MongoDB locally:

```bash
docker compose up -d mongodb
```

Load raw snapshots into MongoDB:

```bash
python3 src/storage/mongodb/load_raw_snapshots.py
```

Default MongoDB settings:

- URI: `mongodb://admin:admin123@localhost:27017/?authSource=admin`
- database: `cyber_risk_raw`

## Suggested Next Steps

- Output Parquet files in `data/curated` and query them with DuckDB.
- Add notebooks in `notebooks/` for CVSS, EPSS, KEV hit rate, and trend visualizations.
- If orchestration is required, add an Airflow, Prefect, or cron-based pipeline.
- If you need the storage/database owner deliverables, use `docs/storage_architecture.md` and `sql/postgres/`.
