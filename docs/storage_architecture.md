# Storage Architecture

This document corresponds to the `Storage / Database Owner` role and defines the storage strategy for the raw layer and processed layer, along with the responsibilities of MongoDB and PostgreSQL.

## Storage Goal

The storage layer in this project is designed to support:

- preserving raw source data
- allowing transformation jobs to be rerun reliably
- enabling analytics queries on structured tables
- controlling primary key consistency, duplicate handling, and indexing strategy

## Layer Design

### 1. Raw Layer

Paths:

- `data/raw/nvd`
- `data/raw/cisa_kev`
- `data/raw/epss`

Purpose:

- store raw API/feed landing files
- keep the source structure unchanged
- preserve lineage and rerunability

Recommended formats:

- NVD: JSON
- CISA KEV: JSON / CSV
- EPSS: JSON

Raw layer rules:

- use append or snapshot style storage
- do not rename fields in the raw layer
- keep filenames source-aware and date-versioned

### 2. Staging Layer

Paths:

- `data/staging/nvd`
- future extension: `data/staging/cisa_kev`
- future extension: `data/staging/epss`

Purpose:

- store normalized and cleaned intermediate datasets
- convert nested JSON into tabular structures
- provide stable inputs before transformation joins

Recommended formats:

- JSONL
- CSV
- Parquet

### 3. Curated Layer

Paths:

- `data/curated/vulnerability_priority`

Purpose:

- store the main analytics table and downstream datasets
- provide datasets for DuckDB, PostgreSQL, and notebooks

Current outputs:

- `vulnerability_priority_latest.csv`
- `vulnerability_priority_latest.jsonl`
- `vulnerability_priority_latest.parquet`

## Database Choice

### MongoDB

Best suited for:

- raw JSON documents
- semi-structured API responses
- source datasets whose schema is not yet stable

Recommended usage in this project:

- `raw_nvd_feeds`
- `raw_cisa_kev_feeds`
- `raw_epss_feeds`

Implementation status in this repo:

- MongoDB runtime is provided via [docker-compose.yml](/Users/bettylin/Documents/UCL-Data-Engineering-Group-Assignment/docker-compose.yml)
- raw snapshot loading is implemented in [load_raw_snapshots.py](/Users/bettylin/Documents/UCL-Data-Engineering-Group-Assignment/src/storage/mongodb/load_raw_snapshots.py)

Reasons:

- the raw data is clearly nested
- document storage is more natural than flattening everything up front
- it is convenient for preserving full payloads and metadata

### PostgreSQL

Best suited for:

- staging tables
- curated master tables
- downstream joins, deduplication, indexing, and BI queries

Recommended usage in this project:

- `staging_nvd_vulnerabilities`
- `dim_cisa_kev`
- `fact_epss_scores`
- `mart_vulnerability_priority`

Reasons:

- the unified schema is already defined
- it is stronger for structured querying and constraints
- it is better than MongoDB for analytics queries and data quality control

## Recommended Ownership Split

### MongoDB stores

- raw NVD response snapshots
- raw CISA KEV snapshots
- raw EPSS snapshots

### PostgreSQL stores

- flattened staging tables
- curated master table
- downstream aggregate tables

## Primary Key Strategy

Canonical primary key:

- `cve_id`

Rules:

- the curated master table uses `cve_id` as the primary key
- if a staging dataset can contain duplicate `cve_id` values, deduplicate it before loading
- the raw layer does not require deduplication, but it should preserve ingest timestamps or snapshot versions

## Deduplication Strategy

### Raw Layer

- do not hard-delete duplicates
- preserve original versions as snapshots

### Staging Layer

- if the same `cve_id` appears multiple times in one batch, keep the newest version
- if source timestamps exist, prefer `last_modified` or the source timestamp to determine the latest record

### Curated Layer

- one `cve_id` must map to exactly one row
- if fields conflict across sources, resolve them by source priority

Source priority:

1. NVD for canonical vulnerability metadata
2. CISA KEV for exploitation status
3. EPSS for probability scores

## Index Strategy

Recommended PostgreSQL indexes:

- primary key on `cve_id`
- btree index on `published`
- btree index on `cvss_base_score`
- btree index on `epss_score`
- btree index on `priority_bucket`
- partial or composite index on `in_kev`, `priority_bucket`

Recommended MongoDB indexes:

- index on the raw payload CVE id path if needed for debugging lookups
- index on ingest timestamp
- index on source name or snapshot date

## Load Pattern

Recommended flow:

1. ingestion writes source data to the raw layer
2. transformation converts raw data into staging datasets
3. the curated master table is exported as Parquet / CSV
4. if loading into databases:
   - raw payloads can be written to MongoDB
   - curated and staging tables can be written to PostgreSQL

## Deliverables For Storage Owner

The `Storage / Database Owner` should deliver at minimum:

- a storage architecture document
- database schema SQL
- primary key, index, and deduplication rules
- collection and table naming conventions

Related files already included in this repo:

- [docs/storage_architecture.md](/Users/bettylin/Documents/UCL-Data-Engineering-Group-Assignment/docs/storage_architecture.md)
- [sql/postgres/01_create_schemas.sql](/Users/bettylin/Documents/UCL-Data-Engineering-Group-Assignment/sql/postgres/01_create_schemas.sql)
- [sql/postgres/02_create_tables.sql](/Users/bettylin/Documents/UCL-Data-Engineering-Group-Assignment/sql/postgres/02_create_tables.sql)
- [sql/postgres/03_create_indexes.sql](/Users/bettylin/Documents/UCL-Data-Engineering-Group-Assignment/sql/postgres/03_create_indexes.sql)
- [docs/mongodb_collections.md](/Users/bettylin/Documents/UCL-Data-Engineering-Group-Assignment/docs/mongodb_collections.md)
- [docker-compose.yml](/Users/bettylin/Documents/UCL-Data-Engineering-Group-Assignment/docker-compose.yml)
- [src/storage/mongodb/load_raw_snapshots.py](/Users/bettylin/Documents/UCL-Data-Engineering-Group-Assignment/src/storage/mongodb/load_raw_snapshots.py)
