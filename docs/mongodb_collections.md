# MongoDB Collections

This document defines the collection design to use if the raw layer is stored in MongoDB.

## Scope

MongoDB in this project is only responsible for raw documents, not the final analytics master table.

## Recommended Database

- Database name: `cyber_risk_raw`

## Collections

### `raw_nvd_feeds`

Purpose:

- store raw JSON snapshots from the NVD API/feed

Suggested fields:

- `_id`
- `source_name`
- `snapshot_date`
- `ingested_at`
- `payload`

Suggested indexes:

- `{ "snapshot_date": 1 }`
- `{ "ingested_at": -1 }`

### `raw_cisa_kev_feeds`

Purpose:

- store raw JSON snapshots from the CISA KEV catalog

Suggested fields:

- `_id`
- `source_name`
- `snapshot_date`
- `ingested_at`
- `payload`

Suggested indexes:

- `{ "snapshot_date": 1 }`
- `{ "ingested_at": -1 }`

### `raw_epss_feeds`

Purpose:

- store raw JSON snapshots from the EPSS feed

Suggested fields:

- `_id`
- `source_name`
- `snapshot_date`
- `ingested_at`
- `payload`

Suggested indexes:

- `{ "snapshot_date": 1 }`
- `{ "ingested_at": -1 }`

## Notes

- raw collections should preserve full payloads without flattening fields first
- if the assignment requires a document database design, this file can be used directly as a deliverable
- downstream joins and analytics should not be done directly in MongoDB
- use [docker-compose.yml](/Users/bettylin/Documents/UCL-Data-Engineering-Group-Assignment/docker-compose.yml) to start MongoDB locally
- use [load_raw_snapshots.py](/Users/bettylin/Documents/UCL-Data-Engineering-Group-Assignment/src/storage/mongodb/load_raw_snapshots.py) to load raw snapshots into these collections
