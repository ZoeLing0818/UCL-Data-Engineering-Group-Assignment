# UCL Data Engineering Group Assignment

This project has been reorganized into a structure that better fits a standard data engineering workflow, with clear separation between ingestion, transformation, and analytics.

## Project Structure

```text
.
|-- data
|   |-- raw
|   |   |-- cisa_kev
|   |   |-- cvelistv5
|   |   |-- epss
|   |   `-- nvd
|   |-- staging
|   `-- curated
|-- dashboard
|-- docs
|-- notebooks
|-- sql
|   `-- postgres
`-- src
    |-- analytics
    |-- ingestion
    |   |-- cvelist
    |   |-- cisa_kev
    |   |-- epss
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

8. `src/storage`
   Store database load utilities such as MongoDB raw snapshot loaders.

9. `dashboard`
   Store the static GitHub Pages dashboard prototype.

## Current Datasets

- `data/raw/nvd/nvdcve-2.0-2026.json`
- `data/raw/cvelistv5/snapshot/cvelistV5-main/...`
- `data/raw/cisa_kev/cisa_kev_catalog.json`
- `data/raw/cisa_kev/cisa_kev_catalog.csv`
- `data/raw/epss/epss_scores.json`
- `data/raw/epss/epss_scores.csv`
- `data/curated/vulnerability_priority/vulnerability_priority_latest.csv`
- `data/curated/product_impact/dim_products_latest.csv`
- `data/curated/product_impact/bridge_cve_products_latest.csv`
- `data/curated/cve_records/dim_cve_records_latest.csv`
- `data/curated/cve_records/bridge_cve_references_latest.csv`
- `data/curated/star_schema/dim_date_latest.csv`
- `data/curated/star_schema/dim_priority_latest.csv`
- `data/curated/star_schema/dim_severity_latest.csv`
- `data/curated/star_schema/dim_cwe_latest.csv`
- `data/curated/star_schema/fact_vulnerability_risk_latest.csv`
- `data/curated/transformation_summaries/*.csv`

## How To Run

Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

Fetch the latest NVD data:

```bash
python3 src/ingestion/nvd/ingest_nvd.py --days 30
```

Download the official CVE record repository snapshot:

```bash
python3 src/ingestion/cvelist/fetch_cvelist_v5.py
```

Fetch the latest EPSS snapshot:

```bash
python3 src/ingestion/epss/fetch_epss.py
```

Fetch the latest CISA KEV data:

```bash
python3 src/ingestion/cisa_kev/fetch_cisa_kev.py
```

Build the curated analytics dataset:

```bash
python3 src/transformation/build_vulnerability_mart.py
python3 src/transformation/build_cve_product_bridge.py
python3 src/transformation/build_cvelist_enrichment.py
python3 src/transformation/build_star_schema.py
python3 src/transformation/build_transformation_summaries.py
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

Open the static dashboard locally:

```bash
python3 -m http.server 8000
```

Then visit:

- `http://localhost:8000/dashboard/`

## Suggested Next Steps

- Output Parquet files in `data/curated` and query them with DuckDB.
- Add notebooks in `notebooks/` for CVSS, EPSS, KEV hit rate, and trend visualizations.
- If orchestration is required, add an Airflow, Prefect, or cron-based pipeline.
- If you need the storage/database owner deliverables, use `docs/storage_architecture.md` and `sql/postgres/`.
- If you need a schema overview for reporting, use `docs/current_schema.md`.
- If you want a demo-ready frontend, use the static dashboard under `dashboard/`.
