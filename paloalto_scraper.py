#!/usr/bin/env python3

"""
Palo Alto PAN-OS Syslog Field Scraper

This script scrapes syslog field descriptions from Palo Alto Networks documentation
for different PAN-OS versions and saves them as separate files for format and field descriptions.

Requirements:
    pip install requests beautifulsoup4 pandas lxml pyyaml
"""

import csv
import requests
from bs4 import BeautifulSoup, NavigableString, Tag
import pandas as pd
import os
import time
import re
import logging
import yaml
from typing import List, Dict, Optional, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PaloAltoLogScraper:
    def __init__(self, config_file='paloalto_scraper_config.yaml', base_delay=None):
        """
        Initialize the scraper with rate limiting and configuration

        Args:
            config_file: Path to the YAML configuration file
            base_delay: Base delay between requests in seconds (overrides config file if provided)
        """
        # Load configuration from file
        config = self._load_config(config_file, label='main config')

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

        # Use provided base_delay or fall back to config file value
        self.base_delay = base_delay if base_delay is not None else config.get('settings', {}).get('base_delay', 1.0)

        # Load PAN-OS versions from configuration file
        self.versions = config.get('versions', [])
        if not self.versions:
            logger.warning("No versions found in configuration file. Scraper will not process any versions.")

        # Set output directory (defaults to current working directory)
        self.output_dir = config.get('settings', {}).get('output_dir', os.getcwd())
        os.makedirs(self.output_dir, exist_ok=True)

        # Load force_rescrape and dry_run flags
        self.force_rescrape = config.get('settings', {}).get('force_rescrape', False)
        self.dry_run = config.get('settings', {}).get('dry_run', False)

        # Configurable pause between versions (previously hardcoded to 2s)
        self.inter_version_delay = config.get('settings', {}).get('inter_version_delay', 2.0)

        # Max HTTP retry attempts per URL
        self.max_retries = config.get('settings', {}).get('max_retries', 3)

        # Load exceptions/corrections file
        exceptions = self._load_config('paloalto_scraper_exceptions.yaml', label='exceptions')
        self.field_name_lookup_corrections_global = exceptions.get('field_name_lookup_corrections', {}).get('global', {})
        self.field_name_lookup_corrections_per_log = exceptions.get('field_name_lookup_corrections', {}).get('per_log_type', {})
        self.variable_name_corrections_global = exceptions.get('variable_name_corrections', {}).get('global', {})
        self.variable_name_corrections_per_log = exceptions.get('variable_name_corrections', {}).get('per_log_type', {})
        self.per_log_corrections = exceptions.get('per_log_corrections', {})

        logger.info(f"Loaded {len(self.versions)} versions from main config")
        logger.info(f"Force rescrape: {self.force_rescrape}")
        logger.info(f"Dry run mode: {self.dry_run}")
        logger.info(f"Loaded {len(self.field_name_lookup_corrections_global)} field name lookup corrections (global), "
                    f"{len(self.variable_name_corrections_global)} variable name corrections (global), "
                    f"{len(self.per_log_corrections)} per-log correction entries")

    def _load_config(self, config_file: str, label: str = 'configuration') -> dict:
        """
        Load configuration from YAML file

        Args:
            config_file: Path to the YAML configuration file
            label: Human-readable label for log messages (e.g. 'main config', 'exceptions')

        Returns:
            Dictionary containing configuration
        """
        # Get the directory where this script is located
        script_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(script_dir, config_file)

        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                logger.info(f"Loaded {label} from {config_path}")
                return config
        except FileNotFoundError:
            logger.error(f"{label.capitalize()} file not found: {config_path}")
            raise
        except yaml.YAMLError as e:
            logger.error(f"Error parsing {label} YAML: {e}")
            raise

    def _version_exists(self, version: dict) -> bool:
        """
        Check if a version has already been scraped (fully).

        A version is considered complete when the number of CSV files in its directory
        is at least equal to the number of configured log types. Fewer files than that
        indicates a partial/interrupted scrape that should be redone.

        Args:
            version: Version dictionary with 'name' and 'log_types' keys

        Returns:
            True if the version directory appears complete, False otherwise
        """
        version_dir = self.get_version_directory(version['name'])

        if os.path.exists(version_dir):
            files = [f for f in os.listdir(version_dir) if f.endswith('.csv')]
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

    def _get_versions_to_scrape(self) -> List[dict]:
        """
        Get the list of versions to scrape based on force_rescrape flag

        Returns:
            List of version dictionaries to scrape
        """
        if self.force_rescrape:
            logger.info("Force rescrape enabled - will scrape all versions")
            return self.versions

        # Filter out existing versions
        versions_to_scrape = [v for v in self.versions if not self._version_exists(v)]

        existing_count = len(self.versions) - len(versions_to_scrape)
        logger.info(f"Found {existing_count} existing versions, {len(versions_to_scrape)} new versions to scrape")

        return versions_to_scrape

    def get_version_directory(self, version_name: str) -> str:
        """
        Get the version directory path

        Args:
            version_name: Version name like '11.1+'

        Returns:
            Path to version directory
        """
        return os.path.join(self.output_dir, version_name)

    def get_page_content(self, url: str) -> Optional[BeautifulSoup]:
        """
        Fetch and parse a web page, retrying on transient failures.

        Args:
            url: URL to fetch

        Returns:
            BeautifulSoup object or None if all attempts failed
        """
        for attempt in range(1, self.max_retries + 1):
            try:
                attempt_label = f" (attempt {attempt}/{self.max_retries})" if attempt > 1 else ""
                logger.info(f"Fetching: {url}{attempt_label}")
                response = self.session.get(url, timeout=30)
                response.raise_for_status()

                # Rate limiting
                time.sleep(self.base_delay)

                return BeautifulSoup(response.content, 'html.parser')

            except requests.exceptions.RequestException as e:
                logger.error(f"Error fetching {url} (attempt {attempt}/{self.max_retries}): {e}")
                if attempt < self.max_retries:
                    wait = self.base_delay * attempt
                    logger.info(f"Retrying in {wait:.1f}s...")
                    time.sleep(wait)

        return None

    def _apply_per_log_corrections(self, items: list, log_type_name: str) -> list:
        """Apply position- or value-based corrections for a specific log type.

        Called only from extract_format_string to fix raw format string tokens
        (e.g., split malformed tokens produced by PA docs bugs).
        """
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

    def extract_format_string(self, soup: BeautifulSoup, log_type_name: str) -> Tuple[Optional[str], List[str]]:
        """
        Extract the syslog format string from the page and apply per-log corrections.

        Args:
            soup: BeautifulSoup object of the page
            log_type_name: Name of the log type (used for per-log corrections)

        Returns:
            (raw_string, corrected_tokens): raw_string is preserved for CSV line 1;
            corrected_tokens is the comma-split list with per-log corrections applied.
            Returns (None, []) if no format string found.
        """
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
        """
        Extract variable name from Field Name.
        Format: "Field Long Name(variable_name ...)" or "Field Long Name (variable_name ...)" -> "variable_name"
        Relaxed \\s*\\( handles malformed parentheticals like "Server Name Indication(sni)".
        """
        match = re.match(r"^.+?\s*\(([^)]+)\)", str(field_name))
        if match:
            # Take first word in parentheses (handles "x or y" cases)
            return match.group(1).split()[0].strip()
        return ""

    def _extract_field_name_lookup(self, field_name: str) -> str:
        """
        Extract the lookup key from a Field Name cell: text before the first '('.
        Relaxed \\s*\\( handles malformed parentheticals.
        """
        match = re.match(r"^(.+?)\s*\(", str(field_name))
        if match:
            return re.sub(r'\s+', ' ', match.group(1)).strip()
        return re.sub(r'\s+', ' ', str(field_name)).strip()

    def extract_field_table(self, soup: BeautifulSoup) -> Optional[pd.DataFrame]:
        """
        Extract the field description table from the page.

        Adds two derived columns after 'Field Name':
          - 'Field Name lookup': text before '(' used for matching format tokens
          - 'Variable Name': snake_case name extracted from parenthetical

        Args:
            soup: BeautifulSoup object of the page

        Returns:
            DataFrame with field descriptions or None if not found
        """
        tables = soup.find_all('table')

        for table in tables:
            headers = [th.get_text(strip=True).lower() for th in table.find_all('th')]

            if 'field name' in ' '.join(headers) or 'field' in ' '.join(headers):
                try:
                    data = []
                    rows = table.find_all('tr')

                    if not rows:
                        continue

                    header_row = rows[0]
                    headers = [th.get_text(strip=True) for th in header_row.find_all(['th', 'td'])]

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
                            # Insert in order: Field Name lookup, then Variable Name
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
        """
        Normalize the 'Field Name lookup' column to match format string tokens.

        Applies global corrections first, then per-log-type corrections.
        Keys are values as they appear in the field table; values are the corresponding
        format string token.
        """
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

    def _lookup_variable_names(self, tokens: List[str], field_table: pd.DataFrame) -> List[str]:
        """
        Replace each format token with its variable name from the field table.

        Lookup order:
          1. DG Hierarchy regex (handles all 3 naming patterns)
          2. Exact match in 'Field Name lookup' column
             - Found + non-empty Variable Name → return Variable Name
             - Found + empty Variable Name → pass token through unchanged,
               AND write the token back to that row's Variable Name column
          3. Not found → pass token through unchanged

        Mutates field_table in-place to fill Variable Name for pass-through tokens
        whose row was found but had an empty Variable Name.
        """
        if field_table is None or 'Field Name lookup' not in field_table.columns:
            return tokens

        # Build exact index: Field Name lookup value → row index
        lookup_index: Dict[str, int] = {}
        for idx, val in enumerate(field_table['Field Name lookup']):
            lookup_key = str(val) if not pd.isna(val) else ""
            if lookup_key and lookup_key not in lookup_index:
                lookup_index[lookup_key] = idx

        result = []
        for token in tokens:
            # 1. DG Hierarchy regex (all 3 patterns)
            dg_match = re.match(
                r"(?:Device Group Hierarchy(?:\s+Level)?|DG Hierarchy Level)\s+(\d+)",
                token
            )
            if dg_match:
                result.append(f"dg_hier_level_{dg_match.group(1)}")
                continue

            # 2. Table lookup: exact match in 'Field Name lookup' column
            row_idx = lookup_index.get(token)
            if row_idx is not None:
                var_name = field_table.at[row_idx, 'Variable Name']
                var_name = "" if pd.isna(var_name) else str(var_name)
                if var_name:
                    result.append(var_name)
                else:
                    # Pass through unchanged; write token to Variable Name column
                    field_table.at[row_idx, 'Variable Name'] = token
                    result.append(token)
                continue

            # 3. Not found — pass through unchanged
            result.append(token)

        return result

    def _apply_variable_name_corrections(
        self,
        tokens: List[str],
        field_table: Optional[pd.DataFrame],
        log_type_name: str
    ) -> Tuple[List[str], Optional[pd.DataFrame]]:
        """
        Apply variable name corrections to both format tokens and the field table.

        Global corrections are applied to all occurrences (replace-all semantics).
        Per-log-type corrections are applied to the FIRST occurrence only in the token
        list — this is intentional: GlobalProtect has "serialnumber" at two positions
        and only the first should become "serial". Field table corrections always use
        replace-all semantics regardless of global/per-log-type.

        Args:
            tokens: List of variable name tokens from _lookup_variable_names
            field_table: Field table DataFrame (may be mutated in-place)
            log_type_name: Name of the log type for per-log corrections

        Returns:
            (corrected_tokens, field_table)
        """
        global_corrections: Dict[str, str] = self.variable_name_corrections_global
        per_log_corrections: Dict[str, str] = self.variable_name_corrections_per_log.get(log_type_name, {})

        # Apply global corrections: replace all occurrences
        corrected_tokens = [global_corrections.get(t, t) for t in tokens]

        # Apply per-log corrections: first occurrence only for each key
        for old, new_val in per_log_corrections.items():
            try:
                pos = corrected_tokens.index(old)
                corrected_tokens[pos] = new_val
            except ValueError:
                pass  # key not in tokens for this log type — skip silently

        # Apply both correction sets to field table Variable Name column (replace all)
        if field_table is not None and 'Variable Name' in field_table.columns:
            all_corrections: Dict[str, str] = dict(global_corrections)
            all_corrections.update(per_log_corrections)
            if all_corrections:
                field_table = field_table.copy()
                field_table['Variable Name'] = field_table['Variable Name'].map(
                    lambda v: all_corrections.get(v, v) if (not pd.isna(v) and str(v) != "") else v
                )

        return corrected_tokens, field_table

    def _get_cell_text_with_formatting(self, cell) -> str:
        """
        Extract text from a BeautifulSoup cell while preserving
        line breaks from HTML block elements.

        Uses BS4 tree traversal to avoid regex manipulation of raw HTML.
        """
        BLOCK_TAGS = frozenset({'p', 'div', 'li', 'dt', 'dd', 'tr',
                                 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'})
        LIST_TAGS = frozenset({'ul', 'ol', 'dl'})
        parts = []

        def _walk(node):
            if isinstance(node, NavigableString):
                # Collapse source-formatting whitespace in text nodes
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
        # Collapse horizontal whitespace (preserve newlines)
        text = re.sub(r'[^\S\n]+', ' ', text)
        # Limit consecutive newlines
        text = re.sub(r'\n{3,}', '\n\n', text)
        # Strip trailing whitespace from each line
        lines = [line.strip() for line in text.split('\n')]
        return '\n'.join(lines).strip()

    def scrape_log_type(self, log_type: dict, version_dir: str) -> bool:
        """
        Scrape a specific log type and save format and table files.

        Args:
            log_type: Dictionary with 'name' and 'url' keys
            version_dir: Directory to save files

        Returns:
            True if both format string and field table were saved successfully.
            A warning is logged when only one of the two was available (partial result).
        """
        logger.info(f"Processing log type: {log_type['name']}")

        soup = self.get_page_content(log_type['url'])
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

        file_prefix = re.sub(r'_Log$', '', log_type['name'])

        if field_table is not None:
            table_filepath = os.path.join(version_dir, f"{file_prefix}_fields.csv")
            try:
                field_table.to_csv(table_filepath, index=False)
                logger.info(f"Saved field table to {table_filepath}")
            except Exception as e:
                logger.error(f"Error saving field table: {e}")

        if raw_format_string:
            format_filepath = os.path.join(version_dir, f"{file_prefix}_format.csv")
            transformed = ",".join(f'"{t}"' for t in output_tokens) if output_tokens else None

            try:
                with open(format_filepath, 'w', encoding='utf-8') as f:
                    f.write(f"{raw_format_string}\n")
                    if transformed:
                        f.write(f"{transformed}\n")
                logger.info(f"Saved format to {format_filepath}"
                            + ("" if transformed else " (no transformation - field table missing)"))
            except Exception as e:
                logger.error(f"Error saving format file: {e}")

        # Warn on partial results
        if raw_format_string is None and field_table is not None:
            logger.warning(f"{log_type['name']}: field table saved but no format string found")
        elif raw_format_string is not None and field_table is None:
            logger.warning(f"{log_type['name']}: format string saved without field table (no transformation)")

        return raw_format_string is not None and field_table is not None

    def _build_consolidated_matrix(self, version_dir: str, log_types: list) -> None:
        """Build the consolidated position × log type matrix and save to panos_syslog_fields.csv.

        Reads line 2 of each *_format.csv (the variable-name transformed line), aligns all
        log types by position index, and writes the matrix with log type names as columns.
        Log types whose format file is missing or has no transformed line are skipped with
        a warning. Positions beyond a log type's last field are left empty.
        """
        columns = {}   # display_name → list of tokens
        ordered_names = []

        for log_type in log_types:
            name = log_type['name']
            file_prefix = re.sub(r'_Log$', '', name)
            format_path = os.path.join(version_dir, f"{file_prefix}_format.csv")

            if not os.path.exists(format_path):
                logger.warning(f"Matrix: no format file for {name}, skipping column")
                continue

            try:
                with open(format_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
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

            # Display name: replace underscores with spaces
            display_name = file_prefix.replace('_', ' ')
            ordered_names.append(display_name)
            columns[display_name] = tokens

        if not columns:
            logger.warning("Matrix: no valid format files found, skipping panos_syslog_fields.csv")
            return

        max_len = max(len(v) for v in columns.values())
        data = {n: columns[n] + [''] * (max_len - len(columns[n])) for n in ordered_names}

        df = pd.DataFrame(data, columns=ordered_names)
        matrix_path = os.path.join(version_dir, 'panos_syslog_fields.csv')
        try:
            df.to_csv(matrix_path, index=False)
            logger.info(
                f"Saved consolidated matrix to {matrix_path} "
                f"({max_len} rows × {len(ordered_names)} columns)"
            )
        except Exception as e:
            logger.error(f"Matrix: cannot save {matrix_path}: {e}")

    def scrape_version(self, version: dict) -> int:
        """
        Scrape all log types for a specific PAN-OS version

        Args:
            version: Version dictionary with 'name' and 'log_types' keys

        Returns:
            Number of successfully processed log types
        """
        logger.info(f"Starting scrape for PAN-OS version {version['name']}")

        # Create version directory
        version_dir = self.get_version_directory(version['name'])
        os.makedirs(version_dir, exist_ok=True)

        # Process each log type
        successful_count = 0

        for log_type in version['log_types']:
            if self.scrape_log_type(log_type, version_dir):
                successful_count += 1

        self._build_consolidated_matrix(version_dir, version['log_types'])

        return successful_count

    def run(self, specific_versions: Optional[List[dict]] = None):
        """
        Run the complete scraping process

        Args:
            specific_versions: Optional list of specific versions to scrape
        """
        # Determine which versions to scrape
        if specific_versions:
            # If specific versions provided, use them directly
            versions_to_scrape = specific_versions
            logger.info(f"Using {len(specific_versions)} specific versions provided by caller")
        else:
            # Otherwise, use the smart filtering based on force_rescrape flag
            versions_to_scrape = self._get_versions_to_scrape()

        logger.info(f"Starting scrape for {len(versions_to_scrape)} versions")

        # Dry run mode - just print what would be scraped
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

        total_processed = 0
        for version in versions_to_scrape:
            try:
                logger.info(f"Processing version {version['name']}")
                successful_count = self.scrape_version(version)
                total_processed += successful_count
                logger.info(f"Completed version {version['name']} - {successful_count} log types processed")

                # Configurable pause between versions (fix #11: was hardcoded to 2s)
                time.sleep(self.inter_version_delay)

            except Exception as e:
                logger.error(f"Error processing version {version['name']}: {e}")
                continue

        logger.info(f"Scraping completed! Total log types processed: {total_processed}")


def main():
    """Main execution function"""
    # Fix #1: no longer hardcoding base_delay=1.0; let the config file value take effect
    scraper = PaloAltoLogScraper()

    # Scrape all versions from config
    scraper.run()

if __name__ == "__main__":
    main()
