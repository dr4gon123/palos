# CLAUDE.md

**Project:** PALOS — PAN-OS Logs Scraper

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Run the scraper
```bash
python3 paloalto_scraper.py
```

### Install dependencies
```bash
pip install requests beautifulsoup4 pandas lxml pyyaml
```

### Dry run (preview without scraping)
Set `dry_run: true` in `paloalto_scraper_config.yaml`, then run the scraper.

### Rebuild ECS mapping skeleton (after re-scraping or variable name corrections)
```bash
python3 generate_ecs_skeleton.py
```


## Architecture

This is a single-file web scraper (`paloalto_scraper.py`) with a YAML config (`paloalto_scraper_config.yaml`). It scrapes Palo Alto Networks PAN-OS syslog field documentation and outputs CSV datasets.

### Data flow
1. Config loads PAN-OS versions and per-log-type URLs from `paloalto_scraper_config.yaml`
2. `PaloAltoLogScraper.run()` iterates versions → log types
3. For each log type page, it extracts:
   - **Format string**: comma-separated ordered field list (e.g. `FUTURE_USE, Receive Time, Serial Number, ...`)
   - **Field table**: HTML table with `Field Name` and `Description` columns
4. Outputs per log type into `{version_name}/` directories:
   - `{LogType}_format.csv`: line 1 = original format string, line 2 = transformed (long names replaced with variable names like `receive_time`)
   - `{LogType}_fields.csv`: field table with added `Field Name lookup` and `Variable Name` columns; empty Variable Names are acceptable for fields with no parenthetical in PA docs
5. After all per-type files exist, `panos_syslog_fields.csv` consolidates all log types into a matrix (position × log type)

### Key methods
- `extract_format_string(soup, log_type_name)` → `(raw_string, list[str])`: regex-extracts the `Format:` section, splits on commas, calls `_apply_per_log_corrections` (raw format token fixes), returns the preserved raw string and corrected token list
- `extract_field_table(soup)`: finds HTML table with "field name" header, parses with BS4, adds `Field Name lookup` (text before `(`, relaxed `\s*\(`) and `Variable Name` columns; empty Variable Names are acceptable
- `_apply_field_name_lookup_corrections(field_table, log_type_name)`: normalizes the `Field Name lookup` column to match format string tokens; uses `field_name_lookup_corrections.global` then `per_log_type`
- `_lookup_variable_names(tokens, field_table)` → `list[str]`: (1) DG Hierarchy regex handles all 3 naming patterns → `dg_hier_level_N`; (2) lookup token in `Field Name lookup` column — if found and non-empty Variable Name, return it; if found and empty Variable Name, write token back to `Variable Name` column and pass through; (3) not found → pass through
- `_apply_variable_name_corrections(tokens, field_table, log_type_name)` → `(list[str], DataFrame)`: applies `variable_name_corrections.global` (replace-all) then `variable_name_corrections.per_log_type` (first-occurrence only on token list) to both the token list and the `Variable Name` column of the field table
- `_apply_per_log_corrections(tokens, log_type_name)`: private helper called only from `extract_format_string`; `match:` (value-based) preferred over `position:` (index-based); supports `new:` and `split_into:`
- `_get_cell_text_with_formatting()`: HTML→text that preserves intentional line breaks from block elements while collapsing source-formatting whitespace

### Config settings
| Key | Default | Effect |
|-----|---------|--------|
| `base_delay` | `1.0` | Seconds between HTTP requests |
| `force_rescrape` | `false` | Skip existing version dirs unless true |
| `dry_run` | `false` | Print plan without fetching |
| `output_dir` | `"."` | Root output directory |

### Output structure
```
{version_name}/              # e.g. 11.1+/
  {LogType}_format.csv       # e.g. Audit_format.csv, Traffic_format.csv (never Audit_Log_format.csv)
  {LogType}_fields.csv       # e.g. Audit_fields.csv — columns: Field Name, Field Name lookup, Variable Name, Description
  panos_syslog_fields.csv    # consolidated matrix across all log types
  ecs/
    panos_ecs_mapping.csv    # unified ECS field mapping (manually curated); see FIELD_MAPPING.md
  ocsf/                      # placeholder for future OCSF mapping
```

The log type name in config (e.g. `Audit_Log`) has `_Log` stripped when generating file names.

**ECS mapping notation** (in `panos_ecs_mapping.csv`):
- `=` direct 1:1 mapping, `->` derived/transformed
- Multiple ECS targets per row: newline-within-cell, each column line corresponds to one target
- See [FIELD_MAPPING.md](FIELD_MAPPING.md) for full notation reference and workflow

### Gotchas
- `force_rescrape` is currently `true` in config — every run re-fetches all pages. Set to `false` to skip existing output.
- `field_name_lookup_corrections.global`: only add an entry when the table key is NEVER the
  correct format token for any log type. If any log uses the table key as its format token,
  use `field_name_lookup_corrections.per_log_type` for the specific logs that need a different
  token. Per_log_type corrections are merged over global (same-key entries in per_log_type
  override global), so an identity mapping (e.g. `"X": "X"`) can suppress a global rename for
  a specific log type (see Audit_Log "Generate Time" in EDGE_CASES.md).
- `per_log_corrections` with `match:` replaces the FIRST occurrence only (uses `list.index()`).
