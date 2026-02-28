# Data Dictionary

This document defines the field semantics, data types, and usage rules for the current vulnerability master table.

## Dataset

- Dataset name: `vulnerability_priority_latest`
- Grain: one row per CVE
- Canonical primary key: `cve_id`
- Base table owner: Data Integration Owner

## Field Dictionary

| Column | Type | Nullable | Source | Description | Example |
| --- | --- | --- | --- | --- | --- |
| `cve_id` | string | No | NVD / KEV / EPSS | Unique vulnerability identifier and primary key | `CVE-2026-0544` |
| `published` | timestamp string | Yes | NVD | CVE publication timestamp | `2026-01-01T09:15:51.113` |
| `last_modified` | timestamp string | Yes | NVD | Most recent CVE update timestamp | `2026-01-06T19:25:10.050` |
| `vuln_status` | string | Yes | NVD | Vulnerability status from NVD | `Analyzed` |
| `cvss_version` | string | Yes | NVD | CVSS version used for scoring | `3.1` |
| `cvss_base_score` | float | Yes | NVD | CVSS base score | `7.3` |
| `cvss_severity` | string | Yes | NVD | CVSS severity category | `HIGH` |
| `cwe_id` | string | Yes | NVD | Associated CWE identifier | `CWE-74` |
| `vendor` | string | Yes | NVD | Affected product vendor | `itsourcecode` |
| `product` | string | Yes | NVD | Affected product name | `school_management_system` |
| `in_kev` | boolean | No | CISA KEV derived | Whether the CVE appears in Known Exploited Vulnerabilities | `false` |
| `kev_date_added` | date string | Yes | CISA KEV | Date added to the KEV catalog | `2025-03-10` |
| `kev_due_date` | date string | Yes | CISA KEV | Recommended remediation due date | `2025-03-31` |
| `kev_ransomware_use` | string | Yes | CISA KEV | Whether the CVE is associated with ransomware campaign usage | `Known` |
| `epss_score` | float | Yes | EPSS | Exploit probability score between 0 and 1 | `0.94321` |
| `epss_percentile` | float | Yes | EPSS | EPSS percentile between 0 and 1 | `0.99871` |
| `priority_bucket` | string | No | Derived | Risk bucket derived from KEV, EPSS, and CVSS | `high` |

## Field Rules

### Primary Key

- `cve_id` is the unique primary key
- duplicates are not allowed
- if the same `cve_id` appears across multiple sources, it must be merged into a single row

### Date Fields

- `published` and `last_modified` keep the original source timestamp format
- `kev_date_added` and `kev_due_date` currently use `YYYY-MM-DD`
- if loaded into a database later, convert them to standard timestamp/date types

### Numeric Fields

- `cvss_base_score`: expected range `0.0` to `10.0`
- `epss_score`: expected range `0.0` to `1.0`
- `epss_percentile`: expected range `0.0` to `1.0`

### Categorical Fields

- `cvss_severity`: common values are `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- `priority_bucket`: currently limited to `low`, `medium`, `high`, `critical`

## Recommended Warehouse Types

If this dataset is loaded into PostgreSQL or DuckDB, use the following types:

| Column | Recommended type |
| --- | --- |
| `cve_id` | `VARCHAR PRIMARY KEY` |
| `published` | `TIMESTAMP` |
| `last_modified` | `TIMESTAMP` |
| `vuln_status` | `VARCHAR` |
| `cvss_version` | `VARCHAR` |
| `cvss_base_score` | `DOUBLE PRECISION` |
| `cvss_severity` | `VARCHAR` |
| `cwe_id` | `VARCHAR` |
| `vendor` | `VARCHAR` |
| `product` | `VARCHAR` |
| `in_kev` | `BOOLEAN` |
| `kev_date_added` | `DATE` |
| `kev_due_date` | `DATE` |
| `kev_ransomware_use` | `VARCHAR` |
| `epss_score` | `DOUBLE PRECISION` |
| `epss_percentile` | `DOUBLE PRECISION` |
| `priority_bucket` | `VARCHAR` |

## Data Quality Checks

At minimum, this table should validate:

1. `cve_id` must not be null or duplicated
2. `cvss_base_score` must be between `0` and `10`
3. `epss_score` must be between `0` and `1`
4. `epss_percentile` must be between `0` and `1`
5. `priority_bucket` must be one of `low`, `medium`, `high`, `critical`
6. when `in_kev = false`, `kev_date_added` and `kev_due_date` should be empty

## Versioning Note

This is the current first version of the master table specification. If new sources or columns are added, update both:

- [docs/schema_mapping.md](/Users/bettylin/Documents/UCL-Data-Engineering-Group-Assignment/docs/schema_mapping.md)
- [docs/data_dictionary.md](/Users/bettylin/Documents/UCL-Data-Engineering-Group-Assignment/docs/data_dictionary.md)
