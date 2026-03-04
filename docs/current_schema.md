# Current Schema

This document describes the current logical schema of the project after adding the product bridge layer.

## Schema Type

The project now uses a hybrid analytical schema:

- a denormalized master table for vulnerability prioritization
- a small dimensional model for affected products
- a CVE record enrichment layer from cvelistV5
- an initial star-schema layer for reporting
- a summary aggregation layer for ETL deliverables
- bridge tables to represent many-to-many relationships

In practical terms, this is no longer just a single flat table. It is now closer to a lightweight vulnerability warehouse.

## Main Layers

### 1. Raw Layer

Raw source files are stored without structural changes:

- NVD CVE feed
- CISA KEV catalog
- EPSS scores

These live under `data/raw/`.

### 2. Staging Layer

The staging layer holds normalized and intermediate datasets:

- normalized NVD vulnerability rows
- CVE-to-product bridge JSONL
- raw cvelistV5 snapshot ready for structured extraction

These live under `data/staging/`.

### 3. Curated Layer

The curated layer now contains multiple analytics-ready tables instead of only one.

It now also includes an initial star-schema output for reporting and BI-style queries.

## Current Curated Tables

### `vulnerability_priority_latest`

Path:

- `data/curated/vulnerability_priority/vulnerability_priority_latest.csv`

Grain:

- one row per CVE

Purpose:

- risk prioritization
- KEV and EPSS enrichment
- high-level analytics

Type:

- denormalized fact-like master table

Primary key:

- `cve_id`

### `dim_products_latest`

Path:

- `data/curated/product_impact/dim_products_latest.csv`

Grain:

- one row per unique CPE product record

Purpose:

- product and platform dimension
- reusable vendor/product lookup

Type:

- dimension table

Primary key:

- `product_key`

### `bridge_cve_products_latest`

Path:

- `data/curated/product_impact/bridge_cve_products_latest.csv`

Grain:

- one row per CVE to product match

Purpose:

- represent the many-to-many relationship between vulnerabilities and affected products
- preserve version range logic from CPE match data

Type:

- bridge table

Primary key:

- logical composite key: `cve_id + product_key + match_criteria_id`

### `dim_cve_records_latest`

Path:

- `data/curated/cve_records/dim_cve_records_latest.csv`

Grain:

- one row per CVE record from cvelistV5

Purpose:

- enrich the CVE domain with official CVE project metadata
- preserve assigner, publication lifecycle, and summary text

Type:

- dimension table

Primary key:

- `cve_id`

### `bridge_cve_references_latest`

Path:

- `data/curated/cve_records/bridge_cve_references_latest.csv`

Grain:

- one row per CVE reference URL inside a container

Purpose:

- store advisory URLs, vendor references, and external links from official CVE records

Type:

- bridge table

### `bridge_cve_problem_types_latest`

Path:

- `data/curated/cve_records/bridge_cve_problem_types_latest.csv`

Grain:

- one row per problem type description in a CVE container

Purpose:

- store problem type text and CWE mappings from cvelistV5

Type:

- bridge table

### `fact_cve_containers_latest`

Path:

- `data/curated/cve_records/fact_cve_containers_latest.csv`

Grain:

- one row per CVE container, including `cna` and `adp_*`

Purpose:

- preserve container-level metadata such as provider org, title, and English descriptions

Type:

- fact-like enrichment table

### `dim_date_latest`

Path:

- `data/curated/star_schema/dim_date_latest.csv`

Grain:

- one row per calendar date used in the fact table

Purpose:

- support reporting and time-based filtering in a star-schema design

Type:

- dimension table

Primary key:

- `date_key`

### `dim_priority_latest`

Path:

- `data/curated/star_schema/dim_priority_latest.csv`

Grain:

- one row per priority bucket

Purpose:

- standardize risk bucket reporting

Type:

- dimension table

Primary key:

- `priority_key`

### `dim_severity_latest`

Path:

- `data/curated/star_schema/dim_severity_latest.csv`

Grain:

- one row per CVSS severity category

Purpose:

- standardize severity reporting

Type:

- dimension table

Primary key:

- `severity_key`

### `dim_cwe_latest`

Path:

- `data/curated/star_schema/dim_cwe_latest.csv`

Grain:

- one row per CWE identifier used by the fact table

Purpose:

- provide a reusable vulnerability weakness dimension

Type:

- dimension table

Primary key:

- `cwe_key`

### `fact_vulnerability_risk_latest`

Path:

- `data/curated/star_schema/fact_vulnerability_risk_latest.csv`

Grain:

- one row per CVE per snapshot date

Purpose:

- provide a fact table for reporting on vulnerability risk, KEV status, EPSS, and product exposure

Type:

- fact table

Primary key:

- `fact_id`

### `transformation_summaries`

Path:

- `data/curated/transformation_summaries/`

Grain:

- varies by dataset

Purpose:

- store ETL summary outputs such as daily new CVEs, CVSS distribution, KEV hit rate, EPSS high-risk grouping, and CWE/vendor/product aggregations

Type:

- aggregate tables

## Logical Model

```text
mart_vulnerability_priority
    cve_id (PK)
        |
        | 1-to-many
        v
bridge_cve_products
    cve_id
    product_key
        |
        | many-to-1
        v
dim_products
    product_key (PK)

dim_cve_records
    cve_id (PK)
        |
        | 1-to-many
        v
bridge_cve_references

dim_cve_records
    cve_id (PK)
        |
        | 1-to-many
        v
bridge_cve_problem_types

dim_cve_records
    cve_id (PK)
        |
        | 1-to-many
        v
fact_cve_containers

fact_vulnerability_risk
    snapshot_date_key -> dim_date
    published_date_key -> dim_date
    last_modified_date_key -> dim_date
    kev_date_added_key -> dim_date
    kev_due_date_key -> dim_date
    priority_key -> dim_priority
    severity_key -> dim_severity
    cwe_key -> dim_cwe
```

## Why This Schema Is Better

Previously, the project only kept:

- one `vendor`
- one `product`

inside the master table.

That was too simple because a single CVE can affect:

- multiple vendors
- multiple products
- multiple versions
- multiple product configurations

The new schema solves that by separating product impact into dedicated tables.

It also adds official CVE record enrichment from cvelistV5, which makes the project richer than a basic NVD-only pipeline.

The new star-schema layer introduces a reusable date dimension and a reporting fact table built from the vulnerability mart.

## Practical Interpretation

If someone asks what schema type this project uses now, the correct short answer is:

`A hybrid relational analytics schema with one CVE master table, product bridge tables, official CVE record enrichment tables, and an initial star-schema reporting layer.`

If you want a simpler answer:

`It is a denormalized vulnerability mart supported by product bridge tables, cvelistV5 enrichment tables, and a star-schema reporting layer.`
