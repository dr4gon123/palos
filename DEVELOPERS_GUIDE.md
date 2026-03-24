# PALOS — Developers Guide

This guide covers the internal architecture of `paloalto_scraper.py`, the corrections
pipeline end-to-end, how to extend the exceptions system, and a key methods reference.
It is written for maintainers and AI assistants working on the codebase.

---

## Architecture Overview

PALOS is a single-file scraper with two supporting YAML files:

```
paloalto_scraper.py             # All scraping logic
paloalto_scraper_config.yaml    # Versions to scrape, URLs, run settings
paloalto_scraper_exceptions.yaml  # Known PAN-OS docs corrections (see below)
```

## Script Flow

```
  paloalto_scraper_config.yaml          paloalto_scraper_exceptions.yaml
  (versions, URLs, settings)            (field/variable corrections)
               │                                      │
               └──────────────────┬───────────────────┘
                                  ▼
                       PaloAltoLogScraper.__init__()
                                  │
                                  ▼
                          run()
                    ┌─────────────────────────┐
                    │  for each version        │
                    │    for each log type     │
                    │      scrape_log_type()   │
                    └──────────┬──────────────┘
                               │ HTTP GET
                               ▼
                       get_page_content()
                       BeautifulSoup (soup)
                               │
               ┌───────────────┴───────────────┐
               │                               │
               ▼                               ▼
  extract_format_string()           extract_field_table()
  ├─ regex-extract Format: section  ├─ find table with "field name" header
  ├─ split on commas → tokens[]     ├─ _extract_field_name_lookup()  ← \s*\(
  └─ _apply_per_log_corrections()   └─ _extract_variable_name()      ← \s*\(
     config: per_log_corrections
  ─────────────────────────────     ──────────────────────────────────────────
  returns:                          returns DataFrame with columns:
    raw_string  (for CSV line 1)      Field Name | Field Name lookup
    tokens[]    (corrected)           Variable Name | Description | ...
               │                               │
               │                               ▼
               │              _apply_field_name_lookup_corrections()
               │              config: field_name_lookup_corrections
               │              (normalizes lookup keys to match format tokens)
               │                               │
               │                               ├──────────► {LogType}_fields.csv
               │                               │
               └───────────────────────────────┘
                               │
                               ▼
                  _lookup_variable_names(tokens, field_table)
                  ┌────────────────────────────────────────────┐
                  │ for each token:                            │
                  │  1. DG Hierarchy regex → dg_hier_level_N  │
                  │  2. exact match in Field Name lookup col   │
                  │     found + non-empty  → return var name  │
                  │     found + empty      → write token back  │
                  │                          pass through      │
                  │     not found          → pass through      │
                  └────────────────────────────────────────────┘
                               │
                               ▼
                  _apply_variable_name_corrections()
                  config: variable_name_corrections
                  ┌────────────────────────────────────────────┐
                  │ global:      replace-all on tokens[]       │
                  │              replace-all on field table     │
                  │ per_log_type: first-occurrence on tokens[] │
                  │              replace-all on field table     │
                  └────────────────────────────────────────────┘
                               │
                               ▼
                        {LogType}_format.csv
                        line 1: raw_string
                        line 2: corrected tokens (quoted CSV)

  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ after all log types ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─

                  _build_consolidated_matrix()
                  reads line 2 of every {LogType}_format.csv
                  aligns by position index across all log types
                               │
                               ▼
                      panos_syslog_fields.csv
                      (rows = positions, columns = log types)

                  _write_consolidated_fields()
                  writes accumulated variable→field mappings
                  (accumulated during each scrape_log_type call)
                               │
                               ▼
                      panos_consolidated_fields.csv
                      (rows = unique variables, sorted by log type coverage)
```

Stages 3–5 (field name lookup corrections → lookup → variable name corrections) are where
the exceptions system lives. See [EDGE_CASES.md](EDGE_CASES.md) for every known correction.

---

## The Corrections Pipeline (per log type)

Each log type goes through `scrape_log_type()`, which calls the pipeline stages in order:

### Stage 1 — `extract_format_string(soup, log_type_name)`

Regex-searches the page text for a `Format:` section. Splits the result on commas to produce
a token list, applies `_apply_per_log_corrections()` to fix format-string-level bugs (e.g.
malformed separators), and returns both the raw string (for CSV line 1) and the corrected
token list. Example token list after splitting:

```
["FUTURE_USE", "Receive Time", "Serial Number", "Type", "Threat/Content Type", ...]
```

### Stage 2 — `extract_field_table(soup)`

Finds the HTML table with a "field name" header, parses it with BeautifulSoup, and returns
a DataFrame. Two columns are inserted after `Field Name`:

- `Field Name lookup`: text before `(` in the field name, used for matching format tokens.
  Uses relaxed `\s*\(` regex to handle malformed parentheticals like `"Server Name Indication(sni)"`.
- `Variable Name`: first word inside the parenthetical (e.g. `"Receive Time (receive_time)"` → `receive_time`).
  Fields with no parenthetical get an empty string — this is acceptable.

`_get_cell_text_with_formatting()` preserves intentional HTML line breaks while collapsing
source-formatting whitespace.

### Stage 3 — `_apply_field_name_lookup_corrections(field_table, log_type_name)`

**This stage normalizes the `Field Name lookup` column before lookup.**

Applies `field_name_lookup_corrections.global` then `field_name_lookup_corrections.per_log_type`
to the `Field Name lookup` column. This bridges cases where the field table's field name
differs from the format string token — for example, "Security Rule UUID" in the field table maps
to "Rule UUID" in the format string.

Implementation: global and per_log_type are merged into a single dict with
`corrections.update(per_log_type)`, so per_log_type entries override global for the same key.
This means a per_log_type entry with an identity mapping (e.g. `"X": "X"`) suppresses a global
rename for that specific log type — the table key stays unchanged and lookup proceeds normally.

Global entries are used only when the correction applies to multiple log types AND the table key
is never the correct format token for any log type. Single-log-type corrections and cases where
some logs need the original table key as their format token use `per_log_type` instead.

The corrected field table is passed to Stage 4 and eventually saved to `*_fields.csv`.

### Stage 4 — `_lookup_variable_names(tokens, field_table)`

Replaces each format token with its variable name from the field table:

1. **DG Hierarchy regex** (all 3 naming patterns, handled first):
   `(?:Device Group Hierarchy(?:\s+Level)?|DG Hierarchy Level)\s+(\d+)` → `dg_hier_level_N`
2. **Table lookup**: search the `Field Name lookup` column for the token
   - Found + non-empty Variable Name → return the Variable Name
   - Found + empty Variable Name → write the token back to the `Variable Name` column, pass token through unchanged
   - Not found → pass token through unchanged

Pass-through tokens (raw long names like "Generated Time") are caught in Stage 5.

### Stage 5 — `_apply_variable_name_corrections(tokens, field_table, log_type_name)`

Applies variable name corrections to both the token list and the `Variable Name` column:

- `variable_name_corrections.global`: applied to all occurrences in the token list (replace-all)
- `variable_name_corrections.per_log_type`: applied to the **first occurrence only** in the token list
- Both correction sets are applied to the field table `Variable Name` column with replace-all semantics

### Stage 6 — `_accumulate_consolidated_fields(output_tokens, field_table, log_type_name)`

Called at the end of each `scrape_log_type()`, this method accumulates variable-to-field mappings
in `self._consolidated_fields` for consolidated output. For each variable in `output_tokens`
(excluding `FUTURE_USE` and empty strings):

- Looks up the field name and description from the field table
- Tracks which log types use each variable
- Uses `DESCRIPTION_PRIORITY` to select the best field name/description when a variable appears
  in multiple log types (Traffic has highest priority, Audit has lowest)

The `DESCRIPTION_PRIORITY` constant at module level defines the priority order:
```python
DESCRIPTION_PRIORITY = [
    "Traffic", "Threat", "URL Filtering", "Data Filtering",
    "Decryption", "Tunnel Inspection", "GlobalProtect", "Authentication",
    "GTP", "SCTP", "HIP Match", "User ID", "IP Tag",
    "Config", "System", "Correlated Events", "Audit",
]
```

### Stage 7 — `_write_consolidated_fields(version_dir)`

Called at the end of `scrape_version()` after all log types have been processed. Writes the
accumulated variable mappings to `panos_consolidated_fields.csv` with columns:

- **Variable Name**: the final variable name after all corrections
- **Field Name**: the field name from the field table (using DESCRIPTION_PRIORITY for selection)
- **Log Types**: comma-separated list of log types that use this variable
- **PAN-OS Description**: the field description (using DESCRIPTION_PRIORITY for selection)

Rows are sorted by log type coverage (descending), then alphabetically by variable name.

---

## Key Methods Reference

| Method | What it does | Notable edge cases handled |
|--------|-------------|---------------------------|
| `extract_format_string(soup, log_type_name)` | Regex-extracts `Format:` section; splits tokens; applies per-log corrections | Returns `(raw_string, list[str])`; multi-line format strings via `DOTALL` |
| `extract_field_table(soup)` | Finds table with "field name" header; returns DataFrame with `Field Name lookup` and `Variable Name` columns | Relaxed `\s*\(` handles malformed parentheticals; empty Variable Names acceptable |
| `_extract_variable_name(field_name)` | Pulls first word from parenthetical | `\s*\(` handles no-space cases; "x or y" → takes first word; no parenthetical → `""` |
| `_extract_field_name_lookup(field_name)` | Extracts text before `(` as lookup key | `\s*\(` handles malformed cases; strips extra whitespace |
| `_apply_field_name_lookup_corrections(field_table, log_type_name)` | Normalizes `Field Name lookup` column to match format tokens | Global then per-log-type corrections |
| `_lookup_variable_names(tokens, field_table)` | Maps format tokens to variable names via field table | DG hierarchy regex first; writes pass-through tokens to Variable Name column when row found but empty |
| `_apply_variable_name_corrections(tokens, field_table, log_type_name)` | Corrects variable names in both token list and field table | Global: replace-all; per-log-type: first-occurrence on token list, replace-all on field table |
| `_apply_per_log_corrections(tokens, log_type_name)` | Position- or value-based fixes on raw format tokens | `match` key for value-based (preferred); `position` for index-based; bounds checked |
| `_get_cell_text_with_formatting(cell)` | HTML cell → text preserving intentional line breaks | Block elements get `\n`; source whitespace collapsed |
| `_accumulate_consolidated_fields(tokens, field_table, log_type_name)` | Accumulates variable-to-field mappings for consolidated output | Uses DESCRIPTION_PRIORITY for field name/description selection |
| `_write_consolidated_fields(version_dir)` | Writes consolidated fields CSV from accumulated data | Sorts by log type count desc, then alphabetically |

---

## Adding a New Exception

All exceptions live in `paloalto_scraper_exceptions.yaml`. Add a comment with the log type
and the reason for each new entry.

### Variable name correction (typo or truncation in Variable Name parenthetical)

The PAN-OS field table has a wrong or truncated variable name in parentheses, or a format
token fails lookup and passes through as a raw long name.

```yaml
variable_name_corrections:
  global:
    "wrong_or_raw_name": "correct_variable_name"  # LogType: explanation
```

Applied to both `*_fields.csv` Variable Name column and the transformed format token list.

### Field name lookup correction (table name differs from format token)

The format string uses a different name than what appears in the field table's `Field Name`
column (before the parenthetical). Use the exact text from the `Field Name lookup` column as the key.

Use **`global`** when the correction applies to multiple log types AND the table key is never
the correct format token for any log type:

```yaml
field_name_lookup_corrections:
  global:
    "Field Name lookup value in table": "Token as it appears in format string"  # LogTypes: reason
```

Use **`per_log_type`** when the correction applies to only one log type, or when some log types
use the original table key as their format token (a global entry would break those logs):

```yaml
field_name_lookup_corrections:
  per_log_type:
    LogType_Name:
      "Field Name lookup value": "Format string token"
```

Use a **per_log_type identity mapping** to suppress a global correction for a specific log type.
Per_log_type overrides global for the same key, so `"X": "X"` keeps the table key unchanged
while other log types still get the global rename applied:

```yaml
field_name_lookup_corrections:
  per_log_type:
    LogType_Name:
      "Field Name lookup value": "Field Name lookup value"  # identity: suppress global rename
```

### Per-log-type variable name correction (first-occurrence semantics)

A specific variable name at a specific occurrence needs different treatment within one log type.
Uses first-occurrence semantics on the token list (subsequent occurrences are unchanged).

```yaml
variable_name_corrections:
  per_log_type:
    LogType_Name:
      "current_variable_name": "correct_variable_name"
```

### Raw format string correction (structural bug in PA docs)

A specific token in the raw format string needs to be replaced or split, before any variable
name lookup. Use when the format string itself is malformed (e.g. wrong separator).

```yaml
per_log_corrections:
  LogType_Name:
    - match: "Exact raw token value"   # value-based, preferred
      split_into: ["token_a", "token_b"]  # expand into multiple tokens
      # OR
      new: "replacement_token"             # replace with a single token
    - position: N                       # 0-indexed, fallback when value not distinctive
      new: "replacement_token"
```

`match` (value-based) is preferred over `position` (index-based) since it is independent
of upstream format string changes. A warning is logged if the match value is not found.

---

## Configuration Reference

`paloalto_scraper_config.yaml`:

| Key | Default | Effect |
|-----|---------|--------|
| `settings.base_delay` | `1.0` | Seconds between HTTP requests |
| `settings.force_rescrape` | `false` | Skip existing version dirs unless true |
| `settings.dry_run` | `false` | Print scrape plan without fetching |
| `settings.output_dir` | `"."` | Root output directory |
| `versions[].name` | — | Version label used as output directory name |
| `versions[].log_types[].name` | — | Log type name used as filename prefix |
| `versions[].log_types[].url` | — | PAN-OS docs URL to scrape |

`paloalto_scraper_exceptions.yaml`:

| Key | Effect |
|-----|--------|
| `field_name_lookup_corrections.global` | Normalizes field table lookup keys to match format tokens (global) |
| `field_name_lookup_corrections.per_log_type` | Same, but only for the specified log type |
| `variable_name_corrections.global` | Corrects variable names in token list (replace-all) and field table Variable Name column |
| `variable_name_corrections.per_log_type` | Same, but first-occurrence semantics on the token list |
| `per_log_corrections` | Raw format string token corrections applied at extraction time |

---

## Running for Development

```bash
# Dry run — print what would be scraped without making any HTTP requests
# Set dry_run: true in paloalto_scraper_config.yaml
python3 paloalto_scraper.py

# Force re-scrape all versions even if output already exists
# Set force_rescrape: true in paloalto_scraper_config.yaml
python3 paloalto_scraper.py

# Install dependencies
pip install requests beautifulsoup4 pandas lxml pyyaml
```
