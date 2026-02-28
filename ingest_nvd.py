#!/usr/bin/env python3
"""
Fetch CVE data from NVD API 2.0 and write:
1) Raw response JSON
2) Normalized JSONL
3) Normalized CSV
4) Optional Parquet (if pyarrow is installed)
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import ssl
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_RESULTS_PER_PAGE = 2000


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Ingest CVE data from NVD API and generate normalized outputs."
    )
    parser.add_argument(
        "--days",
        type=int,
        default=30,
        help="Lookback window in days from now UTC (default: 30).",
    )
    parser.add_argument(
        "--results-per-page",
        type=int,
        default=DEFAULT_RESULTS_PER_PAGE,
        help=f"NVD page size (default: {DEFAULT_RESULTS_PER_PAGE}, max depends on API).",
    )
    parser.add_argument(
        "--output-dir",
        default="data",
        help="Base output directory (default: data).",
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("NVD_API_KEY", ""),
        help="NVD API key (or set NVD_API_KEY env var).",
    )
    parser.add_argument(
        "--start-date",
        default="",
        help="Override start datetime in RFC3339 format, e.g. 2026-01-01T00:00:00.000Z",
    )
    parser.add_argument(
        "--end-date",
        default="",
        help="Override end datetime in RFC3339 format, e.g. 2026-02-01T00:00:00.000Z",
    )
    parser.add_argument(
        "--ca-bundle",
        default="",
        help="Path to CA bundle PEM file for TLS verification.",
    )
    parser.add_argument(
        "--insecure-skip-tls-verify",
        action="store_true",
        help="Disable TLS certificate verification (debug only).",
    )
    return parser.parse_args()


def utc_now() -> datetime:
    return datetime.now(UTC)


def to_nvd_timestamp(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def parse_dt(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value).astimezone(UTC)


def build_query(args: argparse.Namespace) -> dict[str, str | int]:
    if args.start_date:
        start = parse_dt(args.start_date)
    else:
        start = utc_now() - timedelta(days=args.days)

    if args.end_date:
        end = parse_dt(args.end_date)
    else:
        end = utc_now()

    if start >= end:
        raise ValueError("start date must be earlier than end date")

    return {
        "pubStartDate": to_nvd_timestamp(start),
        "pubEndDate": to_nvd_timestamp(end),
        "resultsPerPage": args.results_per_page,
        "startIndex": 0,
    }


def build_ssl_context(args: argparse.Namespace) -> ssl.SSLContext:
    if args.insecure_skip_tls_verify:
        return ssl._create_unverified_context()
    if args.ca_bundle:
        return ssl.create_default_context(cafile=args.ca_bundle)
    return ssl.create_default_context()


def fetch_page(
    query: dict[str, Any], api_key: str, ssl_context: ssl.SSLContext
) -> dict[str, Any]:
    url = f"{NVD_BASE_URL}?{urlencode(query)}"
    req = Request(url)
    if api_key:
        req.add_header("apiKey", api_key)

    with urlopen(req, timeout=60, context=ssl_context) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_all(
    query: dict[str, Any], api_key: str, ssl_context: ssl.SSLContext
) -> dict[str, Any]:
    first = fetch_page(query, api_key, ssl_context)
    total = int(first.get("totalResults", 0))
    per_page = int(first.get("resultsPerPage", query["resultsPerPage"]))
    vulns = list(first.get("vulnerabilities", []))

    start_index = int(query.get("startIndex", 0)) + per_page
    while start_index < total:
        q = dict(query)
        q["startIndex"] = start_index
        page = fetch_page(q, api_key, ssl_context)
        vulns.extend(page.get("vulnerabilities", []))
        start_index += per_page

    out = dict(first)
    out["vulnerabilities"] = vulns
    out["totalResults"] = len(vulns)
    return out


def extract_cwe(cve_obj: dict[str, Any]) -> str:
    weaknesses = cve_obj.get("weaknesses", [])
    for w in weaknesses:
        for d in w.get("description", []):
            value = (d.get("value") or "").strip()
            if value.startswith("CWE-"):
                return value
    return ""


def _to_float_or_none(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None
        try:
            return float(stripped)
        except ValueError:
            return None
    return None


def extract_cvss(metrics: dict[str, Any]) -> tuple[str, float | None, str]:
    # Prefer v3.1, then v3.0, then v2
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key, [])
        if not items:
            continue
        primary = items[0]
        cvss_data = primary.get("cvssData", {})
        version = str(cvss_data.get("version", ""))
        score = _to_float_or_none(cvss_data.get("baseScore"))
        severity = cvss_data.get("baseSeverity", "")
        if not severity:
            severity = primary.get("baseSeverity", "")
        return version, score, severity
    return "", None, ""


def extract_vendor_product(cve_obj: dict[str, Any]) -> tuple[str, str]:
    configurations = cve_obj.get("configurations", [])
    for config in configurations:
        nodes = config.get("nodes", [])
        for node in nodes:
            matches = node.get("cpeMatch", [])
            for match in matches:
                crit = match.get("criteria", "")
                parts = crit.split(":")
                # cpe:2.3:a:vendor:product:version:...
                if len(parts) >= 5 and parts[0] == "cpe" and parts[1] == "2.3":
                    return parts[3], parts[4]
    return "", ""


def normalize_vulnerability(item: dict[str, Any]) -> dict[str, Any]:
    cve = item.get("cve", {})
    metrics = cve.get("metrics", {})
    cvss_version, cvss_score, cvss_severity = extract_cvss(metrics)
    vendor, product = extract_vendor_product(cve)

    return {
        "cve_id": cve.get("id", ""),
        "source_identifier": cve.get("sourceIdentifier", ""),
        "published": cve.get("published", ""),
        "last_modified": cve.get("lastModified", ""),
        "vuln_status": cve.get("vulnStatus", ""),
        "cvss_version": cvss_version,
        "cvss_base_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cwe_id": extract_cwe(cve),
        "vendor": vendor,
        "product": product,
    }


def normalize_all(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return [normalize_vulnerability(v) for v in payload.get("vulnerabilities", [])]


def ensure_dirs(base: Path) -> tuple[Path, Path]:
    raw = base / "raw"
    processed = base / "processed"
    raw.mkdir(parents=True, exist_ok=True)
    processed.mkdir(parents=True, exist_ok=True)
    return raw, processed


def write_json(path: Path, data: Any) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_parquet_if_available(path: Path, rows: list[dict[str, Any]]) -> bool:
    try:
        import pyarrow as pa  # type: ignore
        import pyarrow.parquet as pq  # type: ignore
    except Exception:
        return False

    table = pa.Table.from_pylist(rows)
    pq.write_table(table, path)
    return True


def main() -> int:
    args = parse_args()
    base = Path(args.output_dir)
    raw_dir, processed_dir = ensure_dirs(base)
    run_tag = utc_now().strftime("%Y%m%d_%H%M%S")

    try:
        query = build_query(args)
        ssl_context = build_ssl_context(args)
        payload = fetch_all(query, args.api_key, ssl_context)
    except ValueError as e:
        print(f"Invalid arguments: {e}", file=sys.stderr)
        return 2
    except HTTPError as e:
        detail = e.read().decode("utf-8", errors="ignore")
        print(f"HTTP error {e.code}: {detail}", file=sys.stderr)
        return 3
    except URLError as e:
        print(f"Network error: {e}", file=sys.stderr)
        return 4
    except Exception as e:
        print(f"Unexpected error while fetching data: {e}", file=sys.stderr)
        return 5

    normalized = normalize_all(payload)

    raw_path = raw_dir / f"nvd_cves_raw_{run_tag}.json"
    jsonl_path = processed_dir / f"nvd_cves_normalized_{run_tag}.jsonl"
    csv_path = processed_dir / f"nvd_cves_normalized_{run_tag}.csv"
    parquet_path = processed_dir / f"nvd_cves_normalized_{run_tag}.parquet"

    write_json(raw_path, payload)
    write_jsonl(jsonl_path, normalized)
    write_csv(csv_path, normalized)
    wrote_parquet = write_parquet_if_available(parquet_path, normalized)

    print(f"Fetched CVEs: {len(normalized)}")
    print(f"Raw JSON: {raw_path}")
    print(f"Normalized JSONL: {jsonl_path}")
    print(f"Normalized CSV: {csv_path}")
    if wrote_parquet:
        print(f"Normalized Parquet: {parquet_path}")
    else:
        print("Parquet skipped: pyarrow not installed")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
