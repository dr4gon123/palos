# PALOS — PAN-OS Logs Scraper

PALOS extracts Palo Alto Networks PAN-OS syslog field documentation from the official docs site and transforms it into clean, structured CSV datasets.  It is designed for security engineers and data teams who need machine-readable syslog schemas for parser development, log normalization, or field reference. 

Schema normalization makes firewall logs queryable, correlatable, and actionable across a modern security stack. Normalizing PAN-OS logs against ECS, OCSF, or a custom schema requires exact field names and positions across all log types — information that PAN-OS spreads across separate documentation pages per version. 

PALOS provides that full pipeline: extracting and correcting schemas from official PAN-OS documentation, and translating them into ECS and OCSF field mappings ready for your normalization workflow.

## Quick Start

```bash
pip install requests beautifulsoup4 pandas lxml pyyaml
python3 paloalto_scraper.py
```

Output lands in version-named subdirectories (e.g. `11.1+/`) in the current working directory.

## Output

```
{version}/
  {LogType}_format.csv        # e.g. Traffic_format.csv (not Traffic_Log_format.csv)
  {LogType}_fields.csv        # e.g. Traffic_fields.csv
  panos_syslog_fields.csv     # Consolidated matrix: rows = positions, columns = log types
```

The log type name in config (e.g. `Traffic_Log`) has `_Log` stripped in output file names.

**`{LogType}_format.csv`** — line 1 is the raw comma-separated format string exactly as PAN-OS
documents it (e.g. `FUTURE_USE, Receive Time, Serial Number, ...`). Line 2 is the transformed
version with long names replaced by their snake_case variable names (`FUTURE_USE, receive_time,
serial, ...`). Both lines are quoted CSV so they parse cleanly into arrays.

**`{LogType}_fields.csv`** — the field reference table scraped from PAN-OS docs, with `Field Name lookup`
and `Variable Name` columns inserted after `Field Name`. Variable names are extracted from the
parenthetical in each field's name (e.g. `Serial Number (serial)` → `serial`) and post-processed
to fix PAN-OS docs inconsistencies. See [EDGE_CASES.md](EDGE_CASES.md) for the full list of corrections.

## Field Naming Normalization

Scraped variable names are cross-referenced to standard security schemas for SIEM ingestion and field normalization. See [FIELD_NAMING_NORMALIZATION.md](FIELD_NAMING_NORMALIZATION.md) for full documentation.

| Schema | Status | Output |
|--------|--------|--------|
| ECS (Elastic Common Schema) | 71/297 fields mapped | `11.1+/ecs/panos_ecs_mapping.csv` |
| OCSF | Planned | `11.1+/ocsf/` |

## Configuration

Edit `paloalto_scraper_config.yaml` to customize behaviour:

| Setting | Default | Effect |
|---------|---------|--------|
| `base_delay` | `1.0` | Seconds between HTTP requests (rate limiting) |
| `force_rescrape` | `false` | Re-scrape versions that already exist locally |
| `dry_run` | `false` | Print scrape plan without fetching any pages |
| `output_dir` | `"."` | Root directory for all output |

## Adding a New PAN-OS Version

Add a new entry under `versions` in `paloalto_scraper_config.yaml`:

```yaml
versions:
  - name: "11.2"
    log_types:
      - name: "Traffic_Log"
        url: "https://docs.paloaltonetworks.com/ngfw/11-2/.../traffic-log-fields"
      - name: "Threat_Log"
        url: "https://docs.paloaltonetworks.com/ngfw/11-2/.../threat-log-fields"
      # ... one entry per log type
```

PALOS will skip versions that already exist locally unless `force_rescrape: true`.

## Scraped Log Types (PAN-OS 11.1+)

1. Traffic Log
2. Threat Log
3. URL Filtering Log
4. Data Filtering Log
5. HIP Match Log
6. GlobalProtect Log
7. IP-Tag Log
8. User-ID Log
9. Decryption Log
10. Tunnel Inspection Log
11. SCTP Log
12. Authentication Log
13. Config Log
14. System Log
15. Correlated Events Log
16. GTP Log
17. Audit Log

## PAN-OS Documentation Notes

PAN-OS documentation contains a number of inconsistencies across log types:
variable names truncated in field tables, typos in parentheticals, fields with no
parenthetical at all, long names that differ from the format string, and at least one
literal PAN-OS docs bug (a period used instead of a comma as a field separator). PALOS
corrects all of these automatically through its exceptions system
(`paloalto_scraper_exceptions.yaml`), so the output variable names are consistent and
correct even where the source documentation is not.

Every known correction is catalogued in [EDGE_CASES.md](EDGE_CASES.md), organized by
correction layer, with the root cause and affected log types noted for each entry.

These findings have also been reported to Palo Alto Networks via the Live Community:
["Bugs" on syslog field descriptions documentation (PAN-OS)](https://live.paloaltonetworks.com/t5/general-topics/quot-bugs-quot-on-syslog-field-descriptions-documentation-pan-os/m-p/1249086#M126065)

## For Developers & Maintainers

See [DEVELOPERS_GUIDE.md](DEVELOPERS_GUIDE.md) for:

- The corrections pipeline walkthrough (from raw HTML to final CSV)
- How to add a new exception (field name lookup correction, variable name correction, raw format token fix)
- Key methods reference
- Architecture overview

---

*Not intested in Palo Alto? Check out [Flores - FortiGate Log Message Reference Scraper](https://github.com/dr4gon123/flores)*
