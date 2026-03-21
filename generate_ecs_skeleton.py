#!/usr/bin/env python3
"""
generate_ecs_skeleton.py

One-time bootstrap script that generates the PAN-OS → ECS mapping skeleton CSV.

Reads:
  - {version_dir}/panos_syslog_fields.csv  (matrix: position × log type)
  - {version_dir}/*_fields.csv             (field names and descriptions per log type)

Outputs:
  - {version_dir}/ecs/panos_ecs_mapping.csv

ECS columns (Mapping Type, ECS Field, ECS Type, ECS Description) are left empty
for manual population. FUTURE_USE and empty variable names are excluded.
"""

import csv
import os
import sys

VERSION_DIR = "11.1+"
MATRIX_FILE = os.path.join(VERSION_DIR, "panos_syslog_fields.csv")
OUTPUT_DIR = os.path.join(VERSION_DIR, "ecs")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "panos_ecs_mapping.csv")

# Priority order for selecting field name/description when a variable appears in multiple log types
DESCRIPTION_PRIORITY = [
    "Traffic", "Threat", "URL Filtering", "Data Filtering",
    "Decryption", "Tunnel Inspection", "GlobalProtect", "Authentication",
    "GTP", "SCTP", "HIP Match", "User ID", "IP Tag",
    "Config", "System", "Correlated Events", "Audit",
]

EXCLUDED_VALUES = {"FUTURE_USE", ""}


def log_type_to_filename(log_type: str) -> str:
    """Convert log type name (as in matrix header) to *_fields.csv filename stem."""
    return log_type.replace(" ", "_")


def read_matrix(matrix_path: str) -> dict[str, set[str]]:
    """
    Read panos_syslog_fields.csv and return {variable_name: set(log_types)}.
    Row 1 = log type headers, rows 2+ = variable names per position.
    """
    var_to_logtypes: dict[str, set[str]] = {}

    with open(matrix_path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        headers = next(reader)  # log type names
        log_types = headers  # one column per log type

        for row in reader:
            for i, var_name in enumerate(row):
                var_name = var_name.strip()
                if var_name in EXCLUDED_VALUES:
                    continue
                log_type = log_types[i] if i < len(log_types) else ""
                if not log_type:
                    continue
                var_to_logtypes.setdefault(var_name, set()).add(log_type)

    return var_to_logtypes


def read_fields_file(fields_path: str) -> dict[str, tuple[str, str]]:
    """
    Read a *_fields.csv and return {variable_name: (field_name_lookup, description)}.
    Columns: Field Name, Field Name lookup, Variable Name, Description
    """
    result: dict[str, tuple[str, str]] = {}
    if not os.path.exists(fields_path):
        return result

    with open(fields_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            var_name = row.get("Variable Name", "").strip()
            if not var_name or var_name in EXCLUDED_VALUES:
                continue
            field_name = row.get("Field Name lookup", "").strip()
            description = row.get("Description", "").strip()
            # Only store first occurrence (some log types have repeated variable names)
            if var_name not in result:
                result[var_name] = (field_name, description)

    return result


def build_rows(
    var_to_logtypes: dict[str, set[str]],
    version_dir: str,
) -> list[dict]:
    """
    For each unique variable name, look up Field Name and Description
    using DESCRIPTION_PRIORITY order. Return list of row dicts.
    """
    # Pre-load all fields files in priority order
    fields_by_logtype: dict[str, dict[str, tuple[str, str]]] = {}
    for log_type in DESCRIPTION_PRIORITY:
        stem = log_type_to_filename(log_type)
        path = os.path.join(version_dir, f"{stem}_fields.csv")
        fields_by_logtype[log_type] = read_fields_file(path)

    rows = []
    for var_name, log_type_set in sorted(var_to_logtypes.items()):
        # Determine lookup order: priority list first (intersected with log_type_set), then remainder
        ordered_log_types = [lt for lt in DESCRIPTION_PRIORITY if lt in log_type_set]
        ordered_log_types += sorted(log_type_set - set(ordered_log_types))

        field_name = ""
        description = ""
        for lt in ordered_log_types:
            fields = fields_by_logtype.get(lt, {})
            if var_name in fields:
                field_name, description = fields[var_name]
                break

        # Sort log types by DESCRIPTION_PRIORITY order for consistent output
        sorted_log_types = [lt for lt in DESCRIPTION_PRIORITY if lt in log_type_set]
        sorted_log_types += sorted(log_type_set - set(DESCRIPTION_PRIORITY))
        log_types_str = ",".join(sorted_log_types)

        rows.append({
            "Variable Name": var_name,
            "Field Name": field_name,
            "Log Types": log_types_str,
            "PAN-OS Description": description,
            "Mapping Type": "",
            "ECS Field": "",
            "ECS Type": "",
            "ECS Description": "",
        })

    # Sort: fields in more log types first, then alphabetically by variable name
    rows.sort(key=lambda r: (-r["Log Types"].count(","), r["Variable Name"]))
    return rows


def main():
    if not os.path.exists(MATRIX_FILE):
        print(f"ERROR: {MATRIX_FILE} not found. Run the scraper first.", file=sys.stderr)
        sys.exit(1)

    print(f"Reading matrix from {MATRIX_FILE}...")
    var_to_logtypes = read_matrix(MATRIX_FILE)
    print(f"  Found {len(var_to_logtypes)} unique variable names (excluding FUTURE_USE/empty)")

    print("Looking up field names and descriptions...")
    rows = build_rows(var_to_logtypes, VERSION_DIR)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    fieldnames = [
        "Variable Name", "Field Name", "Log Types", "PAN-OS Description",
        "Mapping Type", "ECS Field", "ECS Type", "ECS Description",
    ]

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Written: {OUTPUT_FILE} ({len(rows)} rows)")

    # Coverage summary
    log_type_counts: dict[str, int] = {}
    for row in rows:
        for lt in row["Log Types"].split(","):
            lt = lt.strip()
            if lt:
                log_type_counts[lt] = log_type_counts.get(lt, 0) + 1
    print("\nFields per log type:")
    for lt in DESCRIPTION_PRIORITY:
        if lt in log_type_counts:
            print(f"  {lt}: {log_type_counts[lt]}")

    print(f"\nOCSF placeholder: {os.path.join(VERSION_DIR, 'ocsf')} (create manually or run again)")


if __name__ == "__main__":
    main()
