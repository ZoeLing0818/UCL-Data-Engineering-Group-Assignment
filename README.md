# UCL Data Engineering Group Assignment

這個專案已經整理成比較符合 data engineering 作業流程的結構，方便你往 ingestion、transformation、analytics 三段式發展。

## Project Structure

```text
.
├── data
│   ├── raw
│   │   ├── cisa_kev
│   │   ├── epss
│   │   └── nvd
│   ├── staging
│   └── curated
├── docs
├── notebooks
└── src
    ├── analytics
    ├── ingestion
    │   ├── cisa_kev
    │   └── nvd
    └── transformation
```

## Recommended Workflow

1. `data/raw`
   放 API / feed 原始落地檔，不做欄位修改。

2. `data/staging`
   放清洗後、可 join 的中間層資料，例如 NVD normalized JSONL / CSV。

3. `data/curated`
   放分析用資料集，例如把 NVD、CISA KEV、EPSS 整併後的 vulnerability mart。

4. `src/ingestion`
   放資料抓取程式。

5. `src/transformation`
   放資料清洗、join、特徵整理程式。

6. `src/analytics`
   放 DuckDB / SQL / notebook 查詢邏輯或分析說明。

## Current Datasets

- `data/raw/nvd/nvdcve-2.0-2026.json`
- `data/raw/cisa_kev/cisa_kev_catalog.json`
- `data/raw/cisa_kev/cisa_kev_catalog.csv`
- `data/raw/epss/epss_scores.json`

## How To Run

抓最新 NVD：

```bash
python3 src/ingestion/nvd/ingest_nvd.py --days 30
```

抓最新 CISA KEV：

```bash
python3 src/ingestion/cisa_kev/fetch_cisa_kev.py
```

整併成分析資料集：

```bash
python3 src/transformation/build_vulnerability_mart.py
```

## Suggested Next Step For Assignment

- 在 `data/curated` 產出 Parquet，接 DuckDB 做查詢。
- 補 `notebooks/` 視覺化 CVSS、EPSS、KEV 命中率與時間趨勢。
- 如果老師要求 orchestration，可以再加 Airflow / Prefect / cron pipeline。
