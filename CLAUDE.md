# CLAUDE.md

**Project:** PALOS — PAN-OS Logs Scraper

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install dependencies
pip install httpx[http2] beautifulsoup4 pandas lxml pyyaml

# Run scraper
python3 paloalto_scraper.py

# Dry run (preview without scraping)
# Set dry_run: true in paloalto_scraper_config.yaml, then run.
```

## Architecture

Single-file async scraper (`paloalto_scraper.py`) with a YAML config. Scrapes PAN-OS syslog
field documentation from Palo Alto Networks docs and outputs CSV datasets.

### Data flow
1. Config loads PAN-OS versions and per-log-type URLs from `paloalto_scraper_config.yaml`
2. `PaloAltoLogScraper.run()` creates one `httpx.AsyncClient` and iterates versions sequentially
3. `scrape_version()` fans out log types concurrently via `asyncio.gather` + `asyncio.Semaphore`
4. For each log type page:
   - **Format string**: comma-separated ordered field list (e.g. `FUTURE_USE, Receive Time, ...`)
   - **Field table**: HTML table with `Field Name` and `Description` columns
5. Outputs per log type into `{version_name}/`:
   - `{LogType}_format.csv`: line 1 = original format string, line 2 = transformed variable names
   - `{LogType}_fields.csv`: field table with added `Field Name lookup` and `Variable Name` columns
6. After all per-type files: `consolidated/panos_syslog_fields.csv` (position × log type matrix)
   and `consolidated/panos_consolidated_fields.csv` (all unique variables with coverage + description)

### Key methods
- `get_page_content(client, url)`: async HTTP fetch with exponential backoff + 429/Retry-After handling
- `extract_format_string(soup, log_type_name)` → `(raw_string, list[str])`: regex-extracts `Format:` section, splits on commas, calls `_apply_per_log_corrections`, returns preserved raw string and corrected tokens
- `extract_field_table(soup)`: finds HTML table with "field name" header; adds `Field Name lookup` (text before `(`) and `Variable Name` columns
- `_apply_field_name_lookup_corrections(field_table, log_type_name)`: normalizes `Field Name lookup` to match format tokens; global then per_log_type
- `_lookup_variable_names(tokens, field_table)`: (1) DG Hierarchy regex → `dg_hier_level_N`; (2) exact lookup in `Field Name lookup` — found + non-empty → return Variable Name; found + empty → write token back and pass through; (3) not found → pass through
- `_apply_variable_name_corrections(tokens, field_table, log_type_name)`: global corrections (replace-all), then per-log-type (first-occurrence only on token list); both applied to field table Variable Name column
- `_apply_per_log_corrections(tokens, log_type_name)`: called only from `extract_format_string`; `match:` preferred over `position:`; supports `new:` and `split_into:`
- `_get_cell_text_with_formatting()`: BS4 tree walk preserving block-element line breaks, collapsing source whitespace

### Config settings (`paloalto_scraper_config.yaml`)
| Key | Default | Effect |
|-----|---------|--------|
| `base_delay` | `1.0` | Politeness sleep per slot after each page fetch |
| `retry_backoff` | `2.0` | Exponential backoff multiplier: `base_delay × (backoff ^ attempt) + jitter` |
| `max_retries` | `3` | Max retry attempts per URL |
| `concurrency` | `5` | `asyncio.Semaphore` size — max parallel log-type fetches per version |
| `inter_version_delay` | `2.0` | Sleep between versions |
| `force_rescrape` | `true` | Re-fetch even if output already exists |
| `dry_run` | `false` | Print plan without fetching |
| `output_dir` | `"."` | Root output directory |

### Output structure
```
{version_name}/              # e.g. 11.1+/
  {LogType}_format.csv       # e.g. Traffic_format.csv  (never Traffic_Log_format.csv)
  {LogType}_fields.csv       # columns: Field Name, Field Name lookup, Variable Name, Description
  consolidated/
    panos_syslog_fields.csv      # position × log type matrix
    panos_consolidated_fields.csv  # all unique variables: field name, log type coverage, description
  ecs/
    panos_ecs_mapping.csv    # manually curated ECS mapping; see FIELD_NAMING_NORMALIZATION.md
```

## Code conventions

All new code must follow these conventions.

### Language & imports
- **Python 3.10+** — use `X | None`, built-in generics, `match` where appropriate.
- **`from __future__ import annotations`** at the top of every module.
- **No `typing` module** — use built-in generics only: `list[str]`, `dict[str, str]`,
  `tuple[str, ...]`, `X | None`. Never `List`, `Dict`, `Optional`, `Tuple`.

### Type hints
- All function signatures must be fully annotated (parameters and return type).
- Return `None` explicitly when a function returns nothing meaningful.
- Use `X | None` for optional values — never `Optional[X]`.
- Use `list[str]`, `dict[str, int]`, `tuple[str, str]` — never `List`, `Dict`, `Tuple`.
- Annotate local variables when the type is not obvious from the right-hand side: `seen: set[str] = set()`.
- Type hints are not enforced at runtime — they exist for static checkers (mypy/pyright) and readability. Do not add `isinstance` guards based solely on a hint.

### File & path operations
- **`pathlib.Path` only** — never `os.path`, `os.makedirs`, `os.getcwd`, or `open()` with
  string paths. Use `Path.read_text()`, `Path.write_text()`, `Path.open()`,
  `Path.mkdir(parents=True, exist_ok=True)`, `Path.iterdir()`.

### HTTP & async
- **`httpx.AsyncClient`** for all HTTP — never `requests`.
- One shared client per run, created in `run()` as a context manager, passed to all callers.
- All network functions are `async def`.
- **Retry** via `get_page_content()`: exponential backoff `base_delay * (retry_backoff ** attempt) + jitter`, 429/Retry-After handling.
- **Concurrency** via `asyncio.Semaphore(self.concurrency)` in `scrape_version()` — never `ThreadPoolExecutor`.
  Politeness sleep (`base_delay`) is inside the semaphore block.

### Logging
- **`logging.getLogger(__name__)`** in every module — never `print()`.
- `logging.basicConfig` only in `main()`, never at module level.
- Use `%`-style or f-string formatting in log calls consistently.

### Pandas
- **No `iterrows()`** — use boolean indexing, `zip` over Series, `map`, or `to_dict('records')`.
- No defensive `.copy()` unless an in-place mutation immediately follows.

### General style
- **`@dataclass` for structured results** — use when a dict has a fixed, known schema (e.g. `FieldInfo`). Prefer attribute access over string-keyed dicts; typos become parse-time errors instead of silent `None`.
- Docstrings: one short line only. No `Args:`/`Returns:` blocks.
- No comments that describe *what* — only *why* (hidden constraints, workarounds).
- Module-level constant for priority index: `_DESCRIPTION_PRIORITY_INDEX` — never call
  `list.index()` in a hot loop.

### Gotchas
- `force_rescrape` is currently `true` in config — every run re-fetches all pages. Set to `false` to skip.
- `field_name_lookup_corrections.global`: only add when the key is NEVER the correct token for any log type.
  Use `per_log_type` for log-specific overrides. Identity mapping `"X": "X"` suppresses a global rename.
- `per_log_corrections` with `match:` replaces the FIRST occurrence only (`list.index()`).
- asyncio is single-threaded: `_accumulate_consolidated_fields` is safe without a lock since it
  contains no `await` — it runs to completion atomically between coroutine switches.
