# Schema Mapping

這份文件定義三個來源資料集如何整合成統一的 vulnerability master table，供 storage、transformation、analytics 組員共同依循。

## Integration Goal

以 `cve_id` 作為跨資料集統一主鍵，將以下三個來源整併成單一主表：

- NVD CVE feed
- CISA KEV catalog
- FIRST EPSS feed

目標輸出資料集：

- `data/curated/vulnerability_priority/vulnerability_priority_latest.csv`
- `data/curated/vulnerability_priority/vulnerability_priority_latest.jsonl`
- `data/curated/vulnerability_priority/vulnerability_priority_latest.parquet`

## Source Systems

| Source | Raw file | Grain | Primary purpose |
| --- | --- | --- | --- |
| NVD | `data/raw/nvd/nvdcve-2.0-2026.json` | one row per CVE | 基礎漏洞資訊、CVSS、CWE、產品資訊 |
| CISA KEV | `data/raw/cisa_kev/cisa_kev_catalog.json` | one row per exploited CVE | 已知遭實際利用標記與 remediation deadline |
| EPSS | `data/raw/epss/epss_scores.json` | one row per CVE score snapshot | 漏洞被利用機率與 percentile |

## Canonical Join Key

- Canonical key: `cve_id`
- Join strategy:
  - NVD: `cve.id`
  - CISA KEV: `cveID`
  - EPSS: `cve`
- Join type:
  - 以 NVD 為主表
  - Left join KEV
  - Left join EPSS

原因：

- NVD 是最完整的 CVE 主清單
- KEV 和 EPSS 都屬補充訊號，不適合當主表

## Naming Convention

統一使用 `snake_case`。

命名原則：

- 主鍵一律用 `cve_id`
- 日期欄位用語意化名稱，如 `published`、`kev_date_added`
- Boolean/flag 欄位用 `in_` 或 `_flag` 類型語意
- 分數欄位保留資料來源語意，如 `cvss_base_score`、`epss_score`

## Source-to-Target Mapping

| Target column | NVD | CISA KEV | EPSS | Rule |
| --- | --- | --- | --- | --- |
| `cve_id` | `cve.id` | `cveID` | `cve` | 統一主鍵 |
| `published` | `cve.published` |  |  | 直接取值 |
| `last_modified` | `cve.lastModified` |  |  | 直接取值 |
| `vuln_status` | `cve.vulnStatus` |  |  | 直接取值 |
| `cvss_version` | `metrics.cvssMetricV31/V30/V2.cvssData.version` |  |  | 優先 v3.1，再 v3.0，再 v2 |
| `cvss_base_score` | `metrics.cvssMetricV31/V30/V2.cvssData.baseScore` |  |  | 取主分數 |
| `cvss_severity` | `metrics...cvssData.baseSeverity` |  |  | 若空則退回 metric-level severity |
| `cwe_id` | `weaknesses[].description[].value` |  |  | 取第一個 `CWE-*` |
| `vendor` | `configurations.nodes.cpeMatch.criteria` |  |  | 由 CPE 字串拆出 vendor |
| `product` | `configurations.nodes.cpeMatch.criteria` |  |  | 由 CPE 字串拆出 product |
| `in_kev` |  | row exists |  | 若 KEV 有對應 CVE 則為 `true` |
| `kev_date_added` |  | `dateAdded` |  | 直接取值 |
| `kev_due_date` |  | `dueDate` |  | 直接取值 |
| `kev_ransomware_use` |  | `knownRansomwareCampaignUse` |  | 直接取值 |
| `epss_score` |  |  | `epss` | 轉為 float |
| `epss_percentile` |  |  | `percentile` | 轉為 float |
| `priority_bucket` | derived | derived | derived | 依 KEV、EPSS、CVSS 規則產生 |

## Current Master Table Spec

目前 master table 欄位如下：

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

- `true`: `cve_id` 存在於 KEV catalog
- `false`: KEV 無對應紀錄

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
  - 其餘情況

## Null Handling Policy

- `cve_id`: 不可為空
- NVD 缺失欄位保留空字串或空值
- KEV / EPSS 若無匹配記錄，不補假值
- `epss_score`、`epss_percentile` 無資料時維持 `null`
- `kev_*` 欄位無資料時維持空字串

## Ownership Notes

Data Integration Owner 應維護：

- 統一欄位命名
- join key 規範
- 欄位 mapping
- master table spec 版本

若後續新增 GHSA / OSV，也應先更新這份 mapping 文件，再交由 transformation 組實作。
