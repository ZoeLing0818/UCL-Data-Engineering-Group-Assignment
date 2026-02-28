# Schema Mapping

This document defines how three source datasets are integrated into a unified vulnerability master table for the storage, transformation, and analytics owners to follow consistently.

## Integration Goal

Use `cve_id` as the cross-source canonical key and merge the following datasets into one master table:

- NVD CVE feed
- CISA KEV catalog
- FIRST EPSS feed

Target output datasets:

- `data/curated/vulnerability_priority/vulnerability_priority_latest.csv`
- `data/curated/vulnerability_priority/vulnerability_priority_latest.jsonl`
- `data/curated/vulnerability_priority/vulnerability_priority_latest.parquet`

## Source Systems

| Source | Raw file | Grain | Primary purpose |
| --- | --- | --- | --- |
| NVD | `data/raw/nvd/nvdcve-2.0-2026.json` | one row per CVE | canonical vulnerability metadata, CVSS, CWE, and product information |
| CISA KEV | `data/raw/cisa_kev/cisa_kev_catalog.json` | one row per exploited CVE | exploitation signal and remediation deadline |
| EPSS | `data/raw/epss/epss_scores.json` | one row per CVE score snapshot | exploit probability and percentile |

## Canonical Join Key

- Canonical key: `cve_id`
- Join strategy:
  - NVD: `cve.id`
  - CISA KEV: `cveID`
  - EPSS: `cve`
- Join type:
  - NVD as the base table
  - left join KEV
  - left join EPSS

Reasoning:

- NVD is the most complete CVE master source
- KEV and EPSS are enrichment signals, not suitable as the base table

## Naming Convention

Use `snake_case` consistently.

Naming rules:

- always use `cve_id` for the primary key
- use semantic names for date fields, such as `published` and `kev_date_added`
- use `in_` or `_flag` style names for boolean/flag fields
- keep source semantics in score fields, such as `cvss_base_score` and `epss_score`

## Source-to-Target Mapping

| Target column | NVD | CISA KEV | EPSS | Rule |
| --- | --- | --- | --- | --- |
| `cve_id` | `cve.id` | `cveID` | `cve` | canonical primary key |
| `published` | `cve.published` |  |  | direct mapping |
| `last_modified` | `cve.lastModified` |  |  | direct mapping |
| `vuln_status` | `cve.vulnStatus` |  |  | direct mapping |
| `cvss_version` | `metrics.cvssMetricV31/V30/V2.cvssData.version` |  |  | prefer v3.1, then v3.0, then v2 |
| `cvss_base_score` | `metrics.cvssMetricV31/V30/V2.cvssData.baseScore` |  |  | use the primary score |
| `cvss_severity` | `metrics...cvssData.baseSeverity` |  |  | if empty, fall back to metric-level severity |
| `cwe_id` | `weaknesses[].description[].value` |  |  | use the first `CWE-*` value |
| `vendor` | `configurations.nodes.cpeMatch.criteria` |  |  | extract vendor from the CPE string |
| `product` | `configurations.nodes.cpeMatch.criteria` |  |  | extract product from the CPE string |
| `in_kev` |  | row exists |  | `true` when a matching KEV row exists |
| `kev_date_added` |  | `dateAdded` |  | direct mapping |
| `kev_due_date` |  | `dueDate` |  | direct mapping |
| `kev_ransomware_use` |  | `knownRansomwareCampaignUse` |  | direct mapping |
| `epss_score` |  |  | `epss` | convert to float |
| `epss_percentile` |  |  | `percentile` | convert to float |
| `priority_bucket` | derived | derived | derived | derived from KEV, EPSS, and CVSS rules |

## Current Master Table Spec

The current master table columns are:

1. `cve_id`
2. `published`
3. `last_modified`
4. `vuln_status`
5. `cvss_version`
6. `cvss_base_score`
7. `cvss_severity`
8. `cwe_id`
9. `vendor`
10. `product`
11. `in_kev`
12. `kev_date_added`
13. `kev_due_date`
14. `kev_ransomware_use`
15. `epss_score`
16. `epss_percentile`
17. `priority_bucket`

## Derived Field Rules

### `in_kev`

- `true`: `cve_id` exists in the KEV catalog
- `false`: no matching KEV record exists

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

## Null Handling Policy

- `cve_id`: must not be null
- missing NVD fields remain empty strings or null values
- if KEV or EPSS has no matching record, do not create artificial values
- `epss_score` and `epss_percentile` remain `null` when unavailable
- `kev_*` fields remain empty strings when unavailable

## Ownership Notes

The `Data Integration Owner` is responsible for maintaining:

- unified column naming
- join key rules
- source-to-target mapping
- master table spec versioning

If GHSA or OSV is added later, update this mapping document first and then hand implementation to the transformation owner.
