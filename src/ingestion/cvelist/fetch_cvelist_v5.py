#!/usr/bin/env python3
"""Download the official CVEProject/cvelistV5 repository snapshot."""

from __future__ import annotations

import argparse
import shutil
import ssl
import sys
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUTPUT_DIR = REPO_ROOT / "data" / "raw" / "cvelistv5"
DEFAULT_ARCHIVE_URL = "https://codeload.github.com/CVEProject/cvelistV5/zip/refs/heads/main"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Download and extract the official CVEProject/cvelistV5 snapshot."
    )
    parser.add_argument(
        "--archive-url",
        default=DEFAULT_ARCHIVE_URL,
        help=f"Archive URL (default: {DEFAULT_ARCHIVE_URL})",
    )
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help="Extraction target directory (default: <repo>/data/raw/cvelistv5).",
    )
    parser.add_argument(
        "--ca-bundle",
        default="",
        help="Path to CA bundle PEM file for TLS verification.",
    )
    parser.add_argument(
        "--insecure-skip-tls-verify",
        action="store_true",
        help="Disable TLS verification (for local debugging only).",
    )
    return parser.parse_args()


def build_ssl_context(args: argparse.Namespace) -> ssl.SSLContext:
    if args.insecure_skip_tls_verify:
        return ssl._create_unverified_context()
    if args.ca_bundle:
        return ssl.create_default_context(cafile=args.ca_bundle)
    try:
        import certifi  # type: ignore

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def download_archive(url: str, destination: Path, ssl_context: ssl.SSLContext) -> None:
    request = Request(
        url,
        headers={
            "Accept": "application/zip",
            "User-Agent": "cvelistv5-fetcher/1.0",
        },
    )
    with urlopen(request, timeout=120, context=ssl_context) as response:
        with destination.open("wb") as handle:
            shutil.copyfileobj(response, handle)


def extract_archive(archive_path: Path, output_dir: Path) -> Path:
    snapshot_dir = output_dir / "snapshot"
    if snapshot_dir.exists():
        shutil.rmtree(snapshot_dir)
    snapshot_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(archive_path, "r") as zip_handle:
        zip_handle.extractall(snapshot_dir)

    extracted_roots = [path for path in snapshot_dir.iterdir() if path.is_dir()]
    if len(extracted_roots) != 1:
        raise RuntimeError("Unexpected archive structure for cvelistV5 snapshot")
    return extracted_roots[0]


def write_metadata(output_dir: Path, archive_url: str, extracted_root: Path) -> Path:
    metadata_path = output_dir / "metadata.txt"
    generated_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    metadata = (
        f"source_url={archive_url}\n"
        f"downloaded_at={generated_at}\n"
        f"extracted_root={extracted_root.name}\n"
    )
    metadata_path.write_text(metadata, encoding="utf-8")
    return metadata_path


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    ssl_context = build_ssl_context(args)

    with tempfile.TemporaryDirectory() as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        archive_path = temp_dir / "cvelistv5.zip"

        try:
            download_archive(args.archive_url, archive_path, ssl_context)
            extracted_root = extract_archive(archive_path, output_dir)
            metadata_path = write_metadata(output_dir, args.archive_url, extracted_root)
        except HTTPError as exc:
            print(f"HTTP error while downloading cvelistV5: {exc.code} {exc.reason}", file=sys.stderr)
            return 1
        except URLError as exc:
            print(f"Network error while downloading cvelistV5: {exc.reason}", file=sys.stderr)
            return 1
        except zipfile.BadZipFile as exc:
            print(f"Downloaded archive is not a valid zip file: {exc}", file=sys.stderr)
            return 1
        except Exception as exc:
            print(f"Unexpected error while downloading cvelistV5: {exc}", file=sys.stderr)
            return 1

    print(f"Downloaded cvelistV5 into {output_dir.resolve()}")
    print(f"Extracted repository snapshot: {extracted_root.resolve()}")
    print(f"Metadata written to: {metadata_path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
