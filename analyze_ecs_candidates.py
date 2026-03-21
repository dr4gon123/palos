#!/usr/bin/env python3
"""
analyze_ecs_candidates.py

Validates PAN-OS → ECS candidate mappings against the official ECS 9.3 schema.

Usage:
  python3 analyze_ecs_candidates.py           # generate ecs_candidates.csv for review
  python3 analyze_ecs_candidates.py --apply   # promote candidates into panos_ecs_mapping.csv
  python3 analyze_ecs_candidates.py --refresh # re-download ECS schema before running
"""

import argparse
import csv
import os
import sys
import urllib.request

VERSION_DIR = "11.1+"
ECS_CACHE = os.path.join(VERSION_DIR, "ecs", "ecs_fields_9.3.csv")
CANDIDATES_FILE = os.path.join(VERSION_DIR, "ecs", "ecs_candidates.csv")
MAPPING_FILE = os.path.join(VERSION_DIR, "ecs", "panos_ecs_mapping.csv")
ECS_URL = "https://raw.githubusercontent.com/elastic/ecs/refs/heads/9.3/generated/csv/fields.csv"

# ---------------------------------------------------------------------------
# Approved candidate ruleset (HIGH CONFIDENCE only)
# Format: panos_var -> (mapping_type, ecs_field, confidence, rationale)
# ---------------------------------------------------------------------------
CANDIDATE_RULES: dict[str, tuple[str, str, str, str]] = {
    # Timestamps / event lifecycle
    "time_generated":      ("=",  "@timestamp",                           "high", "Primary event timestamp — when the firewall generated the log"),
    "receive_time":        ("=",  "event.ingested",                       "high", "When the management plane received the log"),
    "high_res_timestamp":  ("=",  "@timestamp",                           "high", "High-precision override of time_generated (use if non-empty)"),
    "start":               ("=",  "event.start",                          "high", "Session start time (Traffic, Tunnel, GTP)"),

    # Observer (the PAN-OS firewall itself)
    "device_name":         ("=",  "observer.hostname",                    "high", "Firewall hostname"),
    "serial":              ("=",  "observer.serial_number",               "high", "Firewall serial number"),

    # Source/destination geographic extension
    "srcloc":              ("=",  "source.geo.country_name",              "high", "Source country name (PA stores country names, not ISO codes)"),
    "dstloc":              ("=",  "destination.geo.country_name",         "high", "Destination country name (PA stores country names, not ISO codes)"),
    "srcregion":           ("=",  "source.geo.region_name",               "high", "GlobalProtect source region"),
    "srcipv6":             ("=",  "source.ip",                            "high", "IPv6 source address (same semantic as src, IPv6 form)"),
    "xff_ip":              ("=",  "network.forwarded_ip",                 "high", "X-Forwarded-For parsed IP"),

    # TLS / Decryption
    "tls_version":         ("=",  "tls.version",                         "high", "TLS protocol version (e.g., TLS 1.3)"),
    "tls_enc":             ("=",  "tls.cipher",                          "high", "Encryption/cipher algorithm negotiated"),
    "sni":                 ("=",  "tls.client.server_name",              "high", "Server Name Indication from ClientHello"),
    "cn":                  ("=",  "tls.server.x509.subject.common_name", "high", "Server cert subject Common Name"),
    "issuer_cn":           ("=",  "tls.server.x509.issuer.common_name",  "high", "Server cert issuer Common Name"),
    "cert_serial":         ("=",  "tls.server.x509.serial_number",       "high", "Server certificate serial number"),
    "notbefore":           ("=",  "tls.server.x509.not_before",          "high", "Certificate validity start date"),
    "notafter":            ("=",  "tls.server.x509.not_after",           "high", "Certificate validity end date"),

    # Email (Threat log subtypes)
    "sender":              ("=",  "email.from.address",                  "high", "Email sender address"),
    "recipient":           ("=",  "email.to.address",                    "high", "Email recipient address"),
    "subject":             ("=",  "email.subject",                       "high", "Email subject line"),

    # Container / Kubernetes
    "container_id":        ("=",  "container.id",                        "high", "Kubernetes container ID"),
    "pod_name":            ("=",  "orchestrator.resource.name",          "high", "Kubernetes pod name"),
    "pod_namespace":       ("=",  "orchestrator.namespace",              "high", "Kubernetes namespace"),

    # Error
    "error":               ("=",  "error.message",                       "high", "Error message text (GlobalProtect, Decryption)"),
    "error_code":          ("=",  "error.code",                          "high", "Numeric error code"),

    # Host identity (client endpoint — HIP Match, GlobalProtect)
    "machinename":         ("=",  "host.hostname",                       "high", "Client machine hostname"),
    "os":                  ("=",  "host.os.name",                        "high", "Client machine OS name"),
    "client_os":           ("=",  "host.os.name",                        "high", "GlobalProtect client OS name"),
    "client_os_ver":       ("=",  "host.os.version",                     "high", "GlobalProtect client OS version"),

    # User identity (Auth / User-ID logs)
    "user":                ("=",  "user.name",                           "high", "Authenticated username"),
    "ip":                  ("=",  "source.ip",                           "high", "Source IP in Auth/User-ID logs (semantic equivalent to src)"),
}


def download_ecs(cache_path: str, refresh: bool) -> None:
    if os.path.exists(cache_path) and not refresh:
        print(f"Using cached ECS schema: {cache_path}")
        return
    print(f"Downloading ECS schema from {ECS_URL} ...")
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    urllib.request.urlretrieve(ECS_URL, cache_path)
    print(f"Cached to {cache_path}")


def load_ecs_schema(cache_path: str) -> dict[str, dict]:
    """Return {field_path: {type, description}} from ECS CSV."""
    schema = {}
    with open(cache_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            field = row.get("Field", "").strip()
            if field:
                schema[field] = {
                    "type": row.get("Type", "").strip(),
                    "description": row.get("Description", "").strip(),
                }
    # @timestamp is a base field — add if missing
    if "@timestamp" not in schema:
        schema["@timestamp"] = {"type": "date", "description": "Date/time when the event originated."}
    return schema


def load_mapping(mapping_path: str) -> list[dict]:
    with open(mapping_path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def already_mapped(rows: list[dict]) -> set[str]:
    return {r["Variable Name"] for r in rows if r.get("ECS Field")}


def generate_candidates(refresh: bool) -> None:
    download_ecs(ECS_CACHE, refresh)
    ecs_schema = load_ecs_schema(ECS_CACHE)
    print(f"ECS schema loaded: {len(ecs_schema)} fields")

    mapping_rows = load_mapping(MAPPING_FILE)
    mapped_vars = already_mapped(mapping_rows)
    mapping_index = {r["Variable Name"]: r for r in mapping_rows}

    fieldnames = [
        "Variable Name", "Field Name", "Log Types", "PAN-OS Description",
        "Mapping Type", "Candidate ECS Field", "ECS Type", "ECS Description",
        "Confidence", "Rationale", "Schema Valid",
    ]

    candidates = []
    warnings = []

    for panos_var, (mapping_type, ecs_field, confidence, rationale) in CANDIDATE_RULES.items():
        if panos_var not in mapping_index:
            warnings.append(f"  WARNING: '{panos_var}' not found in panos_ecs_mapping.csv — skipping")
            continue
        if panos_var in mapped_vars:
            print(f"  SKIP (already mapped): {panos_var} → {mapping_index[panos_var]['ECS Field']}")
            continue

        row = mapping_index[panos_var]

        # Validate each ECS path (comma-separated for derived fields)
        ecs_paths = [p.strip() for p in ecs_field.split(",")]
        schema_valid = all(p in ecs_schema for p in ecs_paths)
        if not schema_valid:
            missing = [p for p in ecs_paths if p not in ecs_schema]
            warnings.append(f"  SCHEMA INVALID: {panos_var} → {ecs_field} (missing: {missing})")

        # Pull type and description from schema (first path if multiple)
        first_path = ecs_paths[0]
        ecs_type = ecs_schema.get(first_path, {}).get("type", "")
        ecs_desc = ecs_schema.get(first_path, {}).get("description", "")

        candidates.append({
            "Variable Name":       panos_var,
            "Field Name":          row.get("Field Name", ""),
            "Log Types":           row.get("Log Types", ""),
            "PAN-OS Description":  row.get("PAN-OS Description", ""),
            "Mapping Type":        mapping_type,
            "Candidate ECS Field": ecs_field,
            "ECS Type":            ecs_type,
            "ECS Description":     ecs_desc,
            "Confidence":          confidence,
            "Rationale":           rationale,
            "Schema Valid":        "yes" if schema_valid else "NO",
        })

    with open(CANDIDATES_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(candidates)

    print(f"\nWritten: {CANDIDATES_FILE} ({len(candidates)} candidates)")
    high = sum(1 for c in candidates if c["Confidence"] == "high")
    invalid = sum(1 for c in candidates if c["Schema Valid"] == "NO")
    print(f"  High confidence: {high}")
    print(f"  Schema invalid:  {invalid}")

    if warnings:
        print("\nWarnings:")
        for w in warnings:
            print(w)

    print(f"\nReview {CANDIDATES_FILE}, then run with --apply to promote into panos_ecs_mapping.csv")


def apply_candidates() -> None:
    if not os.path.exists(CANDIDATES_FILE):
        print(f"ERROR: {CANDIDATES_FILE} not found. Run without --apply first.", file=sys.stderr)
        sys.exit(1)

    with open(CANDIDATES_FILE, newline="", encoding="utf-8") as f:
        candidates = list(csv.DictReader(f))

    mapping_rows = load_mapping(MAPPING_FILE)
    mapping_index = {r["Variable Name"]: r for r in mapping_rows}

    applied = 0
    skipped_mapped = 0
    skipped_invalid = 0

    for cand in candidates:
        panos_var = cand["Variable Name"]
        if panos_var not in mapping_index:
            continue
        row = mapping_index[panos_var]
        if row.get("ECS Field"):
            skipped_mapped += 1
            continue
        if cand.get("Schema Valid") == "NO":
            print(f"  SKIP (schema invalid): {panos_var} → {cand['Candidate ECS Field']}")
            skipped_invalid += 1
            continue

        row["Mapping Type"] = cand["Mapping Type"]
        row["ECS Field"] = cand["Candidate ECS Field"]
        row["ECS Type"] = cand["ECS Type"]
        row["ECS Description"] = cand["ECS Description"]
        applied += 1

    fieldnames = list(mapping_rows[0].keys())
    with open(MAPPING_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(mapping_rows)

    print(f"Applied {applied} candidates to {MAPPING_FILE}")
    print(f"Skipped {skipped_mapped} already-mapped, {skipped_invalid} schema-invalid")

    # Summary
    final_rows = load_mapping(MAPPING_FILE)
    total_mapped = sum(1 for r in final_rows if r.get("ECS Field"))
    total = len(final_rows)
    print(f"\nCoverage: {total_mapped}/{total} fields mapped ({100*total_mapped//total}%)")


def main():
    parser = argparse.ArgumentParser(description="PAN-OS → ECS candidate analysis")
    parser.add_argument("--apply", action="store_true", help="Promote candidates into panos_ecs_mapping.csv")
    parser.add_argument("--refresh", action="store_true", help="Re-download ECS schema even if cached")
    args = parser.parse_args()

    if args.apply:
        apply_candidates()
    else:
        generate_candidates(args.refresh)


if __name__ == "__main__":
    main()
