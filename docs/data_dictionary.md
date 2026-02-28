# Data Dictionary

這份文件定義目前 vulnerability master table 的欄位語意、型別與使用規則。

## Dataset

- Dataset name: `vulnerability_priority_latest`
- Grain: one row per CVE
- Canonical primary key: `cve_id`
- Base table owner: Data Integration Owner

## Field Dictionary

| Column | Type | Nullable | Source | Description | Example |
| --- | --- | --- | --- | --- | --- |
| `cve_id` | string | No | NVD / KEV / EPSS | 漏洞唯一識別碼，也是主鍵 | `CVE-2026-0544` |
| `published` | timestamp string | Yes | NVD | CVE 首次發布時間 | `2026-01-01T09:15:51.113` |
| `last_modified` | timestamp string | Yes | NVD | CVE 最近更新時間 | `2026-01-06T19:25:10.050` |
| `vuln_status` | string | Yes | NVD | NVD 對此 CVE 的狀態 | `Analyzed` |
| `cvss_version` | string | Yes | NVD | 使用的 CVSS 版本 | `3.1` |
| `cvss_base_score` | float | Yes | NVD | CVSS 基礎分數 | `7.3` |
| `cvss_severity` | string | Yes | NVD | CVSS 嚴重程度分類 | `HIGH` |
| `cwe_id` | string | Yes | NVD | 對應的 CWE 類型 | `CWE-74` |
| `vendor` | string | Yes | NVD | 受影響產品 vendor | `itsourcecode` |
| `product` | string | Yes | NVD | 受影響產品名稱 | `school_management_system` |
| `in_kev` | boolean | No | CISA KEV derived | 是否被列入 Known Exploited Vulnerabilities | `false` |
| `kev_date_added` | date string | Yes | CISA KEV | 加入 KEV catalog 日期 | `2025-03-10` |
| `kev_due_date` | date string | Yes | CISA KEV | 官方建議修補期限 | `2025-03-31` |
| `kev_ransomware_use` | string | Yes | CISA KEV | 是否與 ransomware campaign 有關 | `Known` |
| `epss_score` | float | Yes | EPSS | 被利用機率，範圍 0 到 1 | `0.94321` |
| `epss_percentile` | float | Yes | EPSS | EPSS 百分位，範圍 0 到 1 | `0.99871` |
| `priority_bucket` | string | No | Derived | 綜合 KEV / EPSS / CVSS 的風險分桶 | `high` |

## Field Rules

### Primary Key

- `cve_id` 為唯一主鍵
- 不允許重複
- 若同一 `cve_id` 在多來源出現，必須 merge 成單列

### Date Fields

- `published`、`last_modified` 保留來源時間格式
- `kev_date_added`、`kev_due_date` 目前保留 `YYYY-MM-DD`
- 若後續進資料庫，建議轉成標準 timestamp/date type

### Numeric Fields

- `cvss_base_score`: 建議範圍 `0.0` 到 `10.0`
- `epss_score`: 建議範圍 `0.0` 到 `1.0`
- `epss_percentile`: 建議範圍 `0.0` 到 `1.0`

### Categorical Fields

- `cvss_severity`: 常見值 `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- `priority_bucket`: 目前限定 `low`, `medium`, `high`, `critical`

## Recommended Warehouse Types

若後續進 PostgreSQL / DuckDB，可用以下型別：

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

這張表至少應驗證：

1. `cve_id` 不可為空且不可重複
2. `cvss_base_score` 必須在 `0` 到 `10`
3. `epss_score` 必須在 `0` 到 `1`
4. `epss_percentile` 必須在 `0` 到 `1`
5. `priority_bucket` 必須屬於 `low`, `medium`, `high`, `critical`
6. `in_kev = false` 時，`kev_date_added` 和 `kev_due_date` 應為空

## Versioning Note

這是目前第一版 master table spec。若之後新增來源或欄位，建議同步更新：

- [docs/schema_mapping.md](/Users/bettylin/Documents/UCL-Data-Engineering-Group-Assignment/docs/schema_mapping.md)
- [docs/data_dictionary.md](/Users/bettylin/Documents/UCL-Data-Engineering-Group-Assignment/docs/data_dictionary.md)
