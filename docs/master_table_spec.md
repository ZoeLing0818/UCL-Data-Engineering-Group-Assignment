# Master Table Spec

這份文件是 Data Integration Owner 的正式交付摘要，定義本專案整合後的核心主表規格。

## Table Overview

- Table name: `vulnerability_priority_latest`
- Grain: one row per CVE
- Primary key: `cve_id`
- Base source: NVD
- Enrichment sources:
  - CISA KEV
  - FIRST EPSS

## Business Purpose

這張主表用來支援後續：

- 風險優先排序
- KEV 命中率分析
- EPSS 高風險漏洞分析
- CVSS / CWE / vendor / product 分群查詢
- DuckDB / PostgreSQL / Parquet 分析層

## Canonical Schema

| Column | Type | Required | Description |
| --- | --- | --- | --- |
| `cve_id` | string | Yes | CVE 唯一識別碼 |
| `published` | timestamp string | No | 漏洞發布時間 |
| `last_modified` | timestamp string | No | 漏洞最後更新時間 |
| `vuln_status` | string | No | NVD 漏洞狀態 |
| `cvss_version` | string | No | CVSS 版本 |
| `cvss_base_score` | float | No | CVSS 基礎分數 |
| `cvss_severity` | string | No | CVSS 嚴重度 |
| `cwe_id` | string | No | 主要 CWE 類型 |
| `vendor` | string | No | 受影響 vendor |
| `product` | string | No | 受影響 product |
| `in_kev` | boolean | Yes | 是否存在於 CISA KEV |
| `kev_date_added` | date string | No | 加入 KEV 日期 |
| `kev_due_date` | date string | No | KEV 修補期限 |
| `kev_ransomware_use` | string | No | 是否與 ransomware campaign 有關 |
| `epss_score` | float | No | EPSS exploit probability |
| `epss_percentile` | float | No | EPSS percentile |
| `priority_bucket` | string | Yes | 綜合風險分桶 |

## Source Integration Rules

### Base Table

- 以 NVD CVE feed 為主表
- 每一筆 NVD CVE 對應主表一列

### Join Key

- NVD: `cve.id`
- CISA KEV: `cveID`
- EPSS: `cve`
- 統一轉為 `cve_id`

### Join Type

- NVD left join CISA KEV
- NVD left join EPSS

## Derived Fields

### `in_kev`

- 若 `cve_id` 出現在 KEV catalog，則為 `true`
- 否則為 `false`

### `priority_bucket`

目前規則：

- `critical`
  - `in_kev = true`
  - 或 `epss_score >= 0.9`
  - 或 `cvss_base_score >= 9.0`
- `high`
  - `epss_score >= 0.7`
  - 或 `cvss_base_score >= 7.0`
- `medium`
  - `epss_score >= 0.3`
  - 或 `cvss_base_score >= 4.0`
- `low`
  - 其餘

## Data Quality Rules

1. `cve_id` 不可為空
2. `cve_id` 不可重複
3. `cvss_base_score` 必須介於 `0` 到 `10`
4. `epss_score` 必須介於 `0` 到 `1`
5. `epss_percentile` 必須介於 `0` 到 `1`
6. `priority_bucket` 僅允許 `low`, `medium`, `high`, `critical`

## Storage Recommendations

- Raw layer:
  - 保留原始 JSON / CSV
- Staging layer:
  - 放 normalized NVD / intermediate join outputs
- Curated layer:
  - 放 master table CSV / JSONL / Parquet

## Current Physical Outputs

- [data/curated/vulnerability_priority/vulnerability_priority_latest.csv](/Users/bettylin/Documents/UCL-Data-Engineering-Group-Assignment/data/curated/vulnerability_priority/vulnerability_priority_latest.csv)
- [data/curated/vulnerability_priority/vulnerability_priority_latest.jsonl](/Users/bettylin/Documents/UCL-Data-Engineering-Group-Assignment/data/curated/vulnerability_priority/vulnerability_priority_latest.jsonl)
- [data/curated/vulnerability_priority/vulnerability_priority_latest.parquet](/Users/bettylin/Documents/UCL-Data-Engineering-Group-Assignment/data/curated/vulnerability_priority/vulnerability_priority_latest.parquet)

## Related Documents

- [docs/schema_mapping.md](/Users/bettylin/Documents/UCL-Data-Engineering-Group-Assignment/docs/schema_mapping.md)
- [docs/data_dictionary.md](/Users/bettylin/Documents/UCL-Data-Engineering-Group-Assignment/docs/data_dictionary.md)
