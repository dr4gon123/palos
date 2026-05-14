#!/usr/bin/env python3
"""
Palo Alto PAN-OS Syslog Field Scraper

Scrapes syslog field descriptions from Palo Alto Networks documentation
for different PAN-OS versions and saves them as separate CSV files for
format strings and field descriptions.

Requirements:
    pip install httpx[http2] requests beautifulsoup4 pandas lxml pyyaml
"""
from __future__ import annotations

import asyncio
import csv
import logging
import random
import re
from dataclasses import dataclass
from pathlib import Path

import httpx
import pandas as pd
import yaml
from bs4 import BeautifulSoup, NavigableString, Tag

logger = logging.getLogger(__name__)

# Priority order for selecting field name/description when a variable appears in multiple log types
DESCRIPTION_PRIORITY = [
    "Traffic", "Threat", "URL Filtering", "Data Filtering",
    "Decryption", "Tunnel Inspection", "GlobalProtect", "Authentication",
    "GTP", "SCTP", "HIP Match", "User ID", "IP Tag",
    "Config", "System", "Correlated Events", "Audit",
]

_DESCRIPTION_PRIORITY_INDEX: dict[str, int] = {name: i for i, name in enumerate(DESCRIPTION_PRIORITY)}


@dataclass
class FieldInfo:
    field_name: str
    description: str
    log_types: set[str]
    priority: int


class PaloAltoLogScraper:
    def __init__(self, config_file: str = 'paloalto_scraper_config.yaml'):
        config = self._load_config(config_file, label='main config')
        settings = config.get('settings', {})

        self.base_delay: float = settings.get('base_delay', 1.0)
        self.retry_backoff: float = settings.get('retry_backoff', 2.0)
        self.max_retries: int = settings.get('max_retries', 3)
        self.output_dir: Path = Path(settings.get('output_dir', '.'))
        self.force_rescrape: bool = settings.get('force_rescrape', False)
        self.dry_run: bool = settings.get('dry_run', False)
        self.inter_version_delay: float = settings.get('inter_version_delay', 2.0)
        self.concurrency: int = settings.get('concurrency', 5)
        self.versions: list[dict] = config.get('versions', [])

        if not self.versions:
            logger.warning('No versions found in configuration file.')

        self.output_dir.mkdir(parents=True, exist_ok=True)

        exceptions = self._load_config('paloalto_scraper_exceptions.yaml', label='exceptions')
        self.field_name_lookup_corrections_global: dict[str, str] = exceptions.get('field_name_lookup_corrections', {}).get('global', {})
        self.field_name_lookup_corrections_per_log: dict[str, dict] = exceptions.get('field_name_lookup_corrections', {}).get('per_log_type', {})
        self.variable_name_corrections_global: dict[str, str] = exceptions.get('variable_name_corrections', {}).get('global', {})
        self.variable_name_corrections_per_log: dict[str, dict] = exceptions.get('variable_name_corrections', {}).get('per_log_type', {})
        self.per_log_corrections: dict[str, list] = exceptions.get('per_log_corrections', {})

        self._consolidated_fields: dict[str, FieldInfo] = {}

        logger.info(f'Loaded {len(self.versions)} versions from main config')
        logger.info(f'Force rescrape: {self.force_rescrape}')
        logger.info(f'Dry run mode: {self.dry_run}')
        logger.info(f'Loaded {len(self.field_name_lookup_corrections_global)} field name lookup corrections (global), '
                    f'{len(self.variable_name_corrections_global)} variable name corrections (global), '
                    f'{len(self.per_log_corrections)} per-log correction entries')

    def _load_config(self, config_file: str, label: str = 'configuration') -> dict:
        config_path = Path(__file__).parent / config_file
        try:
            config = yaml.safe_load(config_path.read_text())
            logger.info(f'Loaded {label} from {config_path}')
            return config
        except FileNotFoundError:
            logger.error(f'{label.capitalize()} file not found: {config_path}')
            raise
        except yaml.YAMLError as e:
            logger.error(f'Error parsing {label} YAML: {e}')
            raise

    def _version_exists(self, version: dict) -> bool:
        """Check if a version has already been scraped (fully)."""
        version_dir = self.get_version_directory(version['name'])
        if version_dir.exists():
            files = [p for p in version_dir.iterdir() if p.suffix == '.csv']
            expected_min = len(version.get('log_types', []))
            if len(files) >= expected_min:
                logger.info(f"Version {version['name']} already complete ({len(files)} CSV files)")
                return True
            elif files:
                logger.warning(
                    f"Version {version['name']} appears incomplete: "
                    f"found {len(files)} CSV files, expected at least {expected_min}. "
                    f"Will re-scrape."
                )
        return False

    def _get_versions_to_scrape(self) -> list[dict]:
        if self.force_rescrape:
            logger.info("Force rescrape enabled - will scrape all versions")
            return self.versions
        versions_to_scrape = [v for v in self.versions if not self._version_exists(v)]
        existing_count = len(self.versions) - len(versions_to_scrape)
        logger.info(f"Found {existing_count} existing versions, {len(versions_to_scrape)} new versions to scrape")
        return versions_to_scrape

    def get_version_directory(self, version_name: str) -> Path:
        return self.output_dir / version_name

    async def get_page_content(self, client: httpx.AsyncClient, url: str) -> BeautifulSoup | None:
        """Fetch and parse a web page, retrying with exponential backoff on transient failures."""
        for attempt in range(self.max_retries + 1):
            try:
                attempt_label = f" (attempt {attempt + 1}/{self.max_retries + 1})" if attempt > 0 else ""
                logger.info(f"Fetching: {url}{attempt_label}")
                r = await client.get(url)

                if r.status_code == 429:
                    wait = int(r.headers.get(
                        'Retry-After', self.base_delay * (self.retry_backoff ** attempt)))
                    logger.warning(f'Rate limited (429). Waiting {wait}s '
                                   f'(attempt {attempt + 1}/{self.max_retries + 1})')
                    await asyncio.sleep(wait)
                    continue

                r.raise_for_status()
                return BeautifulSoup(r.content, 'html.parser')

            except (httpx.TransportError, httpx.HTTPStatusError) as e:
                if attempt < self.max_retries:
                    wait = self.base_delay * (self.retry_backoff ** attempt) + random.uniform(0, 1)
                    logger.warning(f'Error fetching {url}: {e}. '
                                   f'Retrying in {wait:.1f}s '
                                   f'(attempt {attempt + 1}/{self.max_retries + 1})')
                    await asyncio.sleep(wait)
                else:
                    logger.error(f'Failed to fetch {url} after {self.max_retries + 1} attempts: {e}')
        return None

    def _apply_per_log_corrections(self, items: list, log_type_name: str) -> list:
        """Apply position- or value-based corrections for a specific log type."""
        for correction in self.per_log_corrections.get(log_type_name, []):
            if 'match' in correction:
                target = correction['match']
                try:
                    pos = items.index(target)
                except ValueError:
                    logger.warning(
                        f"Per-log correction for {log_type_name}: "
                        f"match '{target}' not found in items; skipping."
                    )
                    continue
            elif 'position' in correction:
                pos = correction['position']
                if pos < 0 or pos >= len(items):
                    logger.warning(
                        f"Per-log correction for {log_type_name} has out-of-bounds "
                        f"position {pos} (list length {len(items)}); skipping."
                    )
                    continue
            else:
                logger.warning(
                    f"Per-log correction for {log_type_name} has neither "
                    f"'position' nor 'match' key; skipping."
                )
                continue

            if 'new' in correction:
                items[pos] = correction['new']
            elif 'split_into' in correction:
                items = items[:pos] + correction['split_into'] + items[pos + 1:]

        return items

    def extract_format_string(self, soup: BeautifulSoup, log_type_name: str) -> tuple[str | None, list[str]]:
        """Extract the syslog format string and apply per-log corrections."""
        text_content = soup.get_text()
        format_match = re.search(r'Format\s*:\s*(.+?)(?:\n\s*\n|\n{2,})', text_content, re.IGNORECASE | re.DOTALL)

        if format_match:
            raw_string = format_match.group(1).strip()
            raw_string = re.sub(r'\s+', ' ', raw_string)
            logger.info(f"Found format string: {raw_string[:100]}...")
            tokens = [item.strip() for item in raw_string.split(',')]
            tokens = self._apply_per_log_corrections(tokens, log_type_name)
            return raw_string, tokens

        logger.warning("No format string found on page")
        return None, []

    def _extract_variable_name(self, field_name: str) -> str:
        match = re.match(r"^.+?\s*\(([^)]+)\)", str(field_name))
        if match:
            return match.group(1).strip()
        return ""

    def _extract_field_name_lookup(self, field_name: str) -> str:
        match = re.match(r"^(.+?)\s*\(", str(field_name))
        if match:
            return re.sub(r'\s+', ' ', match.group(1)).strip()
        return re.sub(r'\s+', ' ', str(field_name)).strip()

    def extract_field_table(self, soup: BeautifulSoup) -> pd.DataFrame | None:
        """Extract the field description table from the page."""
        for table in soup.find_all('table'):
            headers = [th.get_text(strip=True).lower() for th in table.find_all('th')]

            if 'field name' in ' '.join(headers) or 'field' in ' '.join(headers):
                try:
                    rows = table.find_all('tr')
                    if not rows:
                        continue

                    header_row = rows[0]
                    headers = [th.get_text(strip=True) for th in header_row.find_all(['th', 'td'])]

                    data = []
                    for row in rows[1:]:
                        cells = row.find_all(['td', 'th'])
                        if len(cells) >= len(headers):
                            row_data = [self._get_cell_text_with_formatting(cell) for cell in cells[:len(headers)]]
                            data.append(row_data)

                    if data:
                        df = pd.DataFrame(data, columns=headers)
                        if 'Field Name' in df.columns:
                            field_name_idx = df.columns.get_loc('Field Name')
                            variable_names = [self._extract_variable_name(fn) for fn in df['Field Name']]
                            lookup_names = [self._extract_field_name_lookup(fn) for fn in df['Field Name']]
                            df.insert(field_name_idx + 1, 'Field Name lookup', lookup_names)
                            df.insert(field_name_idx + 2, 'Variable Name', variable_names)
                        logger.info(f"Extracted field table: {len(df)} rows")
                        return df

                except Exception as e:
                    logger.error(f"Error parsing field table: {e}")
                    continue

        logger.warning("No field description table found")
        return None

    def _apply_field_name_lookup_corrections(self, field_table: pd.DataFrame, log_type_name: str) -> pd.DataFrame:
        """Normalize 'Field Name lookup' column to match format string tokens."""
        if 'Field Name lookup' not in field_table.columns:
            return field_table

        corrections = dict(self.field_name_lookup_corrections_global)
        corrections.update(self.field_name_lookup_corrections_per_log.get(log_type_name, {}))

        if not corrections:
            return field_table

        field_table = field_table.copy()
        field_table['Field Name lookup'] = field_table['Field Name lookup'].map(
            lambda v: corrections.get(v, v)
        )
        return field_table

    def _lookup_variable_names(self, tokens: list[str], field_table: pd.DataFrame) -> list[str]:
        """Replace each format token with its variable name from the field table."""
        if field_table is None or 'Field Name lookup' not in field_table.columns:
            return tokens

        lookup_index: dict[str, int] = {}
        for idx, val in enumerate(field_table['Field Name lookup']):
            lookup_key = str(val) if not pd.isna(val) else ""
            if lookup_key and lookup_key not in lookup_index:
                lookup_index[lookup_key] = idx

        result = []
        for token in tokens:
            dg_match = re.match(
                r"(?:Device Group Hierarchy(?:\s+Level)?|DG Hierarchy Level)\s+(\d+)",
                token
            )
            if dg_match:
                result.append(f"dg_hier_level_{dg_match.group(1)}")
                continue

            row_idx = lookup_index.get(token)
            if row_idx is not None:
                var_name = field_table.at[row_idx, 'Variable Name']
                var_name = "" if pd.isna(var_name) else str(var_name)
                if var_name:
                    result.append(var_name)
                else:
                    field_table.at[row_idx, 'Variable Name'] = token
                    result.append(token)
                continue

            result.append(token)

        return result

    def _apply_variable_name_corrections(
        self,
        tokens: list[str],
        field_table: pd.DataFrame | None,
        log_type_name: str,
    ) -> tuple[list[str], pd.DataFrame | None]:
        """Apply variable name corrections to both format tokens and the field table."""
        global_corrections: dict[str, str] = self.variable_name_corrections_global
        per_log_corrections: dict[str, str] = self.variable_name_corrections_per_log.get(log_type_name, {})

        corrected_tokens = [global_corrections.get(t, t) for t in tokens]

        for old, new_val in per_log_corrections.items():
            try:
                pos = corrected_tokens.index(old)
                corrected_tokens[pos] = new_val
            except ValueError:
                pass

        if field_table is not None and 'Variable Name' in field_table.columns:
            all_corrections: dict[str, str] = dict(global_corrections)
            all_corrections.update(per_log_corrections)
            if all_corrections:
                field_table = field_table.copy()
                field_table['Variable Name'] = field_table['Variable Name'].map(
                    lambda v: all_corrections.get(v, v) if (not pd.isna(v) and str(v) != "") else v
                )

        return corrected_tokens, field_table

    def _accumulate_consolidated_fields(
        self,
        output_tokens: list[str],
        field_table: pd.DataFrame | None,
        log_type_name: str,
    ) -> None:
        """Accumulate variable-to-field mappings for consolidated output."""
        var_to_info: dict[str, tuple[str, str]] = {}
        if field_table is not None and 'Variable Name' in field_table.columns:
            valid = field_table[
                field_table['Variable Name'].notna() &
                (field_table['Variable Name'].astype(str) != '')
            ]
            fn_series = (
                valid['Field Name lookup'].fillna('').astype(str)
                if 'Field Name lookup' in valid.columns
                else pd.Series([''] * len(valid), index=valid.index)
            )
            desc_series = (
                valid['Description'].fillna('').astype(str)
                if 'Description' in valid.columns
                else pd.Series([''] * len(valid), index=valid.index)
            )
            for var, fn, desc in zip(valid['Variable Name'].astype(str), fn_series, desc_series):
                if var not in var_to_info:
                    var_to_info[var] = (fn, desc)

        display_name = re.sub(r'_Log$', '', log_type_name).replace('_', ' ')
        priority = _DESCRIPTION_PRIORITY_INDEX.get(display_name, len(DESCRIPTION_PRIORITY))

        for var_name in output_tokens:
            if not var_name or var_name == 'FUTURE_USE':
                continue

            if var_name not in self._consolidated_fields:
                field_name, description = var_to_info.get(var_name, ('', ''))
                self._consolidated_fields[var_name] = FieldInfo(
                    field_name=field_name,
                    description=description,
                    log_types={display_name},
                    priority=priority,
                )
            else:
                info = self._consolidated_fields[var_name]
                info.log_types.add(display_name)
                if priority < info.priority:
                    field_name, description = var_to_info.get(var_name, ('', ''))
                    if field_name or description:
                        info.field_name = field_name
                        info.description = description
                        info.priority = priority

    def _get_cell_text_with_formatting(self, cell) -> str:
        """Extract text from a BS4 cell while preserving line breaks from block elements."""
        BLOCK_TAGS = frozenset({'p', 'div', 'li', 'dt', 'dd', 'tr',
                                 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'})
        LIST_TAGS = frozenset({'ul', 'ol', 'dl'})
        parts = []

        def _walk(node):
            if isinstance(node, NavigableString):
                parts.append(re.sub(r'\s+', ' ', str(node)))
            elif isinstance(node, Tag):
                name = node.name.lower() if node.name else ''
                if name == 'br':
                    parts.append('\n')
                elif name in BLOCK_TAGS or name in LIST_TAGS:
                    parts.append('\n')
                    for child in node.children:
                        _walk(child)
                    parts.append('\n')
                else:
                    for child in node.children:
                        _walk(child)

        for child in cell.children:
            _walk(child)

        text = ''.join(parts)
        text = re.sub(r'[^\S\n]+', ' ', text)
        text = re.sub(r'\n{3,}', '\n\n', text)
        lines = [line.strip() for line in text.split('\n')]
        return '\n'.join(lines).strip()

    async def scrape_log_type(self, client: httpx.AsyncClient, log_type: dict, version_dir: Path) -> bool:
        """Scrape a specific log type and save format and table files."""
        logger.info(f"Processing log type: {log_type['name']}")

        soup = await self.get_page_content(client, log_type['url'])
        if not soup:
            logger.error(f"Failed to fetch page for {log_type['name']}")
            return False

        raw_format_string, format_tokens = self.extract_format_string(soup, log_type['name'])
        field_table = self.extract_field_table(soup)

        if field_table is not None:
            field_table = self._apply_field_name_lookup_corrections(field_table, log_type['name'])

        if format_tokens and field_table is not None:
            output_tokens = self._lookup_variable_names(format_tokens, field_table)
            output_tokens, field_table = self._apply_variable_name_corrections(
                output_tokens, field_table, log_type['name']
            )
        elif format_tokens:
            output_tokens = format_tokens
        else:
            output_tokens = []

        if output_tokens:
            self._accumulate_consolidated_fields(output_tokens, field_table, log_type['name'])

        file_prefix = re.sub(r'_Log$', '', log_type['name'])

        if field_table is not None:
            table_filepath = version_dir / f"{file_prefix}_fields.csv"
            try:
                field_table.to_csv(table_filepath, index=False)
                logger.info(f"Saved field table to {table_filepath}")
            except Exception as e:
                logger.error(f"Error saving field table: {e}")

        if raw_format_string:
            format_filepath = version_dir / f"{file_prefix}_format.csv"
            transformed = ",".join(f'"{t}"' for t in output_tokens) if output_tokens else None
            try:
                content = f"{raw_format_string}\n"
                if transformed:
                    content += f"{transformed}\n"
                format_filepath.write_text(content, encoding='utf-8')
                logger.info(f"Saved format to {format_filepath}"
                            + ("" if transformed else " (no transformation - field table missing)"))
            except Exception as e:
                logger.error(f"Error saving format file: {e}")

        if raw_format_string is None and field_table is not None:
            logger.warning(f"{log_type['name']}: field table saved but no format string found")
        elif raw_format_string is not None and field_table is None:
            logger.warning(f"{log_type['name']}: format string saved without field table (no transformation)")

        return raw_format_string is not None and field_table is not None

    def _build_consolidated_matrix(self, version_dir: Path, log_types: list) -> None:
        """Build the consolidated position × log type matrix and save to panos_syslog_fields.csv."""
        columns: dict[str, list[str]] = {}
        ordered_names: list[str] = []

        for log_type in log_types:
            name = log_type['name']
            file_prefix = re.sub(r'_Log$', '', name)
            format_path = version_dir / f"{file_prefix}_format.csv"

            if not format_path.exists():
                logger.warning(f"Matrix: no format file for {name}, skipping column")
                continue

            try:
                lines = format_path.read_text(encoding='utf-8').splitlines(keepends=True)
            except Exception as e:
                logger.error(f"Matrix: cannot read {format_path}: {e}")
                continue

            if len(lines) < 2 or not lines[1].strip():
                logger.warning(f"Matrix: {file_prefix}_format.csv has no transformed line 2, skipping column")
                continue

            try:
                tokens = next(csv.reader([lines[1].strip()]))
            except Exception as e:
                logger.error(f"Matrix: cannot parse {file_prefix}_format.csv line 2: {e}")
                continue

            display_name = file_prefix.replace('_', ' ')
            ordered_names.append(display_name)
            columns[display_name] = tokens

        if not columns:
            logger.warning("Matrix: no valid format files found, skipping panos_syslog_fields.csv")
            return

        max_len = max(len(v) for v in columns.values())
        data = {n: columns[n] + [''] * (max_len - len(columns[n])) for n in ordered_names}

        df = pd.DataFrame(data, columns=ordered_names)
        consolidated_dir = version_dir / 'consolidated'
        consolidated_dir.mkdir(exist_ok=True)
        matrix_path = consolidated_dir / 'panos_syslog_fields.csv'
        try:
            df.to_csv(matrix_path, index=False)
            logger.info(
                f"Saved consolidated matrix to {matrix_path} "
                f"({max_len} rows × {len(ordered_names)} columns)"
            )
        except Exception as e:
            logger.error(f"Matrix: cannot save {matrix_path}: {e}")

    def _write_consolidated_fields(self, version_dir: Path) -> None:
        """Write the consolidated fields CSV from accumulated data."""
        if not self._consolidated_fields:
            logger.warning("No consolidated fields to write")
            return

        rows = []
        for var_name, info in self._consolidated_fields.items():
            sorted_log_types = [lt for lt in DESCRIPTION_PRIORITY if lt in info.log_types]
            sorted_log_types += sorted(info.log_types - set(DESCRIPTION_PRIORITY))
            log_types_str = ','.join(sorted_log_types)
            rows.append({
                'Variable Name': var_name,
                'Field Name': info.field_name,
                'Log Types': log_types_str,
                'PAN-OS Description': info.description,
            })

        rows.sort(key=lambda r: (-r['Log Types'].count(',') - 1, r['Variable Name']))

        consolidated_dir = version_dir / 'consolidated'
        consolidated_dir.mkdir(exist_ok=True)
        fields_path = consolidated_dir / 'panos_consolidated_fields.csv'
        try:
            with fields_path.open('w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'Variable Name', 'Field Name', 'Log Types', 'PAN-OS Description'
                ])
                writer.writeheader()
                writer.writerows(rows)
            logger.info(f"Saved consolidated fields to {fields_path} ({len(rows)} rows)")
        except Exception as e:
            logger.error(f"Cannot save consolidated fields: {e}")

    async def scrape_version(self, client: httpx.AsyncClient, version: dict) -> int:
        """Scrape all log types for a specific PAN-OS version."""
        logger.info(f"Starting scrape for PAN-OS version {version['name']}")
        self._consolidated_fields: dict[str, FieldInfo] = {}

        version_dir = self.get_version_directory(version['name'])
        version_dir.mkdir(parents=True, exist_ok=True)

        sem = asyncio.Semaphore(self.concurrency)

        async def process_one(log_type: dict) -> bool:
            async with sem:
                result = await self.scrape_log_type(client, log_type, version_dir)
                await asyncio.sleep(self.base_delay)
                return result

        results = await asyncio.gather(*[process_one(lt) for lt in version['log_types']])

        self._build_consolidated_matrix(version_dir, version['log_types'])
        self._write_consolidated_fields(version_dir)

        return sum(bool(r) for r in results)

    async def run(self, specific_versions: list[dict] | None = None) -> None:
        """Run the complete scraping process."""
        if specific_versions:
            versions_to_scrape = specific_versions
            logger.info(f"Using {len(specific_versions)} specific versions provided by caller")
        else:
            versions_to_scrape = self._get_versions_to_scrape()

        logger.info(f"Starting scrape for {len(versions_to_scrape)} versions")

        if self.dry_run:
            logger.info("=" * 60)
            logger.info("DRY RUN MODE - No actual scraping will be performed")
            logger.info("=" * 60)
            logger.info(f"\nVersions that would be scraped ({len(versions_to_scrape)} total):")
            for i, version in enumerate(versions_to_scrape, 1):
                version_dir = self.get_version_directory(version['name'])
                logger.info(f"  {i}. Version {version['name']} -> {version_dir}")
                for log_type in version['log_types']:
                    logger.info(f"      - {log_type['name']}: {log_type['url']}")
            logger.info("\n" + "=" * 60)
            logger.info(f"Total versions to scrape: {len(versions_to_scrape)}")
            logger.info("=" * 60)
            return

        async with httpx.AsyncClient(
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                                   '(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'},
            timeout=httpx.Timeout(30.0),
            follow_redirects=True,
        ) as client:
            for version in versions_to_scrape:
                try:
                    logger.info(f"Processing version {version['name']}")
                    successful_count = await self.scrape_version(client, version)
                    logger.info(f"Completed version {version['name']} - {successful_count} log types processed")
                    await asyncio.sleep(self.inter_version_delay)
                except Exception as e:
                    logger.error(f"Error processing version {version['name']}: {e}")

        logger.info("Scraping completed!")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    asyncio.run(PaloAltoLogScraper().run())


if __name__ == '__main__':
    main()
