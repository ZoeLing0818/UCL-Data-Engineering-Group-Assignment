# Master Table Spec

This document is the formal summary deliverable for the `Data Integration Owner` and defines the core integrated master table used in this project.

## Table Overview

- Table name: `vulnerability_priority_latest`
- Grain: one row per CVE
- Primary key: `cve_id`
- Base source: NVD
- Enrichment sources:
  - CISA KEV
  - FIRST EPSS

## Business Purpose

This master table supports:

- risk prioritization
- KEV hit rate analysis
- high-risk EPSS analysis
- CVSS / CWE / vendor / product segmentation
- DuckDB / PostgreSQL / Parquet analytics workflows

## Canonical Schema

| Column | Type | Required | Description |
| --- | --- | --- | --- |
| `cve_id` | string | Yes | unique CVE identifier |
| `published` | timestamp string | No | vulnerability publication timestamp |
| `last_modified` | timestamp string | No | latest vulnerability update timestamp |
| `vuln_status` | string | No | NVD vulnerability status |
| `cvss_version` | string | No | CVSS version |
| `cvss_base_score` | float | No | CVSS base score |
| `cvss_severity` | string | No | CVSS severity |
| `cwe_id` | string | No | primary CWE identifier |
| `vendor` | string | No | affected vendor |
| `product` | string | No | affected product |
| `in_kev` | boolean | Yes | whether the CVE exists in CISA KEV |
| `kev_date_added` | date string | No | date added to KEV |
| `kev_due_date` | date string | No | KEV remediation deadline |
| `kev_ransomware_use` | string | No | whether linked to ransomware campaign usage |
| `epss_score` | float | No | EPSS exploit probability |
| `epss_percentile` | float | No | EPSS percentile |
| `priority_bucket` | string | Yes | derived risk bucket |

## Source Integration Rules

### Base Table

- use the NVD CVE feed as the base table
- each NVD CVE maps to one row in the master table

### Join Key

- NVD: `cve.id`
- CISA KEV: `cveID`
- EPSS: `cve`
- all are normalized into `cve_id`

### Join Type

- NVD left join CISA KEV
- NVD left join EPSS

## Derived Fields

### `in_kev`

- `true` when the `cve_id` exists in the KEV catalog
- `false` otherwise

### `priority_bucket`

Current rules:

- `critical`
  - `in_kev = true`
  - or `epss_score >= 0.9`
  - or `cvss_base_score >= 9.0`
- `high`
  - `epss_score >= 0.7`
  - or `cvss_base_score >= 7.0`
- `medium`
  - `epss_score >= 0.3`
  - or `cvss_base_score >= 4.0`
- `low`
  - all other cases

## Data Quality Rules

1. `cve_id` must not be null
2. `cve_id` must be unique
3. `cvss_base_score` must be between `0` and `10`
4. `epss_score` must be between `0` and `1`
5. `epss_percentile` must be between `0` and `1`
6. `priority_bucket` must be one of `low`, `medium`, `high`, `critical`

## Storage Recommendations

- Raw layer:
  - preserve original JSON / CSV
- Staging layer:
  - store normalized NVD and intermediate join outputs
- Curated layer:
  - store the master table as CSV / JSONL / Parquet

## Current Physical Outputs

- [data/curated/vulnerability_priority/vulnerability_priority_latest.csv](/Users/bettylin/Documents/UCL-Data-Engineering-Group-Assignment/data/curated/vulnerability_priority/vulnerability_priority_latest.csv)
- [data/curated/vulnerability_priority/vulnerability_priority_latest.jsonl](/Users/bettylin/Documents/UCL-Data-Engineering-Group-Assignment/data/curated/vulnerability_priority/vulnerability_priority_latest.jsonl)
- [data/curated/vulnerability_priority/vulnerability_priority_latest.parquet](/Users/bettylin/Documents/UCL-Data-Engineering-Group-Assignment/data/curated/vulnerability_priority/vulnerability_priority_latest.parquet)

## Related Documents

- [docs/schema_mapping.md](/Users/bettylin/Documents/UCL-Data-Engineering-Group-Assignment/docs/schema_mapping.md)
- [docs/data_dictionary.md](/Users/bettylin/Documents/UCL-Data-Engineering-Group-Assignment/docs/data_dictionary.md)
