#!/usr/bin/env python3
"""Load raw vulnerability data snapshots into MongoDB."""

from __future__ import annotations

import argparse
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pymongo import MongoClient
from pymongo.collection import Collection


REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DATA_DIR = REPO_ROOT / "data" / "raw"
DEFAULT_MONGO_URI = "mongodb://admin:admin123@localhost:27017/?authSource=admin"
DEFAULT_DATABASE = "cyber_risk_raw"

SOURCE_CONFIGS = (
    {
        "source_name": "nvd",
        "collection_name": "raw_nvd_feeds",
        "glob": "nvd/*.json",
    },
    {
        "source_name": "cisa_kev",
        "collection_name": "raw_cisa_kev_feeds",
        "glob": "cisa_kev/*.json",
    },
    {
        "source_name": "epss",
        "collection_name": "raw_epss_feeds",
        "glob": "epss/*.json",
    },
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Load raw NVD, CISA KEV, and EPSS snapshots into MongoDB."
    )
    parser.add_argument(
        "--data-dir",
        default=str(DEFAULT_DATA_DIR),
        help="Raw data directory (default: <repo>/data/raw).",
    )
    parser.add_argument(
        "--mongo-uri",
        default=os.getenv("MONGODB_URI", DEFAULT_MONGO_URI),
        help="MongoDB connection URI.",
    )
    parser.add_argument(
        "--database",
        default=os.getenv("MONGODB_DATABASE", DEFAULT_DATABASE),
        help="MongoDB database name.",
    )
    parser.add_argument(
        "--source",
        choices=("all", "nvd", "cisa_kev", "epss"),
        default="all",
        help="Limit loading to a single source.",
    )
    parser.add_argument(
        "--snapshot-date",
        default="",
        help="Snapshot date label in YYYY-MM-DD format. Defaults to today's UTC date.",
    )
    return parser.parse_args()


def utc_now() -> datetime:
    return datetime.now(UTC)


def load_json(path: Path) -> dict[str, Any] | list[Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def ensure_indexes(collection: Collection) -> None:
    collection.create_index("snapshot_date")
    collection.create_index("ingested_at")
    collection.create_index("source_name")
    collection.create_index(
        [("source_name", 1), ("file_name", 1)],
        unique=True,
        name="uniq_source_file",
    )


def upsert_snapshot(
    collection: Collection,
    source_name: str,
    file_path: Path,
    snapshot_date: str,
) -> str:
    payload = load_json(file_path)
    document = {
        "source_name": source_name,
        "snapshot_date": snapshot_date,
        "ingested_at": utc_now(),
        "file_name": file_path.name,
        "file_path": str(file_path.resolve()),
        "payload": payload,
    }

    result = collection.update_one(
        {"source_name": source_name, "file_name": file_path.name},
        {"$set": document},
        upsert=True,
    )

    if result.upserted_id is not None:
        return "inserted"
    if result.modified_count > 0:
        return "updated"
    return "unchanged"


def iter_source_files(data_dir: Path, source_name: str) -> list[tuple[str, str, Path]]:
    matches: list[tuple[str, str, Path]] = []
    for config in SOURCE_CONFIGS:
        if source_name != "all" and config["source_name"] != source_name:
            continue
        for path in sorted(data_dir.glob(config["glob"])):
            matches.append((config["source_name"], config["collection_name"], path))
    return matches


def main() -> int:
    args = parse_args()
    data_dir = Path(args.data_dir)
    snapshot_date = args.snapshot_date or utc_now().strftime("%Y-%m-%d")

    files = iter_source_files(data_dir, args.source)
    if not files:
        print(f"No raw JSON files found under {data_dir}")
        return 1

    client = MongoClient(args.mongo_uri)
    database = client[args.database]

    inserted = 0
    updated = 0
    unchanged = 0

    try:
        client.admin.command("ping")
        for source_name, collection_name, file_path in files:
            collection = database[collection_name]
            ensure_indexes(collection)
            status = upsert_snapshot(collection, source_name, file_path, snapshot_date)
            if status == "inserted":
                inserted += 1
            elif status == "updated":
                updated += 1
            else:
                unchanged += 1
            print(f"{status:9} {collection_name}: {file_path.name}")
    finally:
        client.close()

    total = inserted + updated + unchanged
    print(f"Processed snapshots: {total}")
    print(f"Inserted: {inserted}")
    print(f"Updated: {updated}")
    print(f"Unchanged: {unchanged}")
    print(f"Database: {args.database}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
