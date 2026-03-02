# PALOS — Palo Alto Documentation Edge Cases

PAN-OS syslog documentation contains a number of inconsistencies across log types:
variable names truncated in field table parentheticals, outright typos, fields with no
parenthetical at all, long names in the format string that differ from auto-detected table
mappings, and at least one literal PAN-OS docs structural bug. PALOS corrects all of these
automatically through `paloalto_scraper_exceptions.yaml`. This file catalogs every known
correction, its root cause, and the affected log types.

Corrections are applied in three layers, matching the internal pipeline order. See
[DEVELOPERS_GUIDE.md](DEVELOPERS_GUIDE.md) for how each layer fits into the pipeline.

---

## Layer 1 — Per-Log Format String Corrections

Applied at extraction time inside `extract_format_string()`. These correct raw format string
tokens before any variable name lookup — fixing PAN-OS docs structural bugs that produce
malformed or incorrect tokens in the comma-split list. Configured under `per_log_corrections`.

### Correlated_Events_Log — Period instead of comma (PAN-OS docs literal bug)

PAN-OS documentation uses a period instead of a comma between "Source Address" and "Source User"
in the Correlated Events format string, producing the single token:

```
"Source Address. Source User"
```

This is a literal bug in the PAN-OS documentation page — not a PALOS parsing issue.
Correction: `match: "Source Address. Source User"` with `split_into: ["src", "srcuser"]`
expands the single malformed token back into two correct tokens. `match` (value-based)
is used rather than `position` (index-based) so the fix is independent of upstream field
additions.

### GlobalProtect_Log — Serial field collision

PAN-OS's GlobalProtect field table contains two serial-related rows:

| Field Name | Field Name lookup | Variable Name |
|---|---|---|
| `Serial # (serial)` | `Serial #` | `serial` |
| `Serial Number (serialnumber)` | `Serial Number` | `serialnumber` |

The format string has `"Serial Number"` at two positions:
- Position 2 (firewall serial) → should map to `serial` via `Serial # (serial)`
- Position 20 (machine serial) → should map to `serialnumber` via `Serial Number (serialnumber)`

Without correction both positions would look up `"Serial Number"` and find `Serial Number
(serialnumber)` → `serialnumber`.

Correction: `per_log_corrections.GlobalProtect_Log` uses `match: "Serial Number"` (first
occurrence only) with `new: "Serial #"`. This renames position 2's token to `"Serial #"` at
extraction time, so lookup finds the correct `Serial # (serial)` row → `serial`. Position 20
keeps `"Serial Number"` and looks up `Serial Number (serialnumber)` → `serialnumber`. Both
field table rows retain their correct variable names untouched.

---

## Layer 2 — Field Name Lookup Corrections

Applied to the `Field Name lookup` column of the field table before variable name lookup.
These normalize field table lookup keys to match the corresponding format string token
exactly, bridging cases where the field table name and format string name differ.
Configured under `field_name_lookup_corrections.global` and `per_log_type`.

### Auto-detected fields (no config entry needed)

The `_extract_variable_name()` and `_extract_field_name_lookup()` helpers use a relaxed
`\s*\(` regex (no required space before the opening parenthesis). This automatically handles
malformed parentheticals:

| Field Name in PA docs | Auto-detected variable name | Notes |
|---|---|---|
| `Server Name Indication(sni)` | `sni` | No space before `(` — relaxed regex fixes |
| `Tunnel Inspection Rule(tunnel_insp_rule)` | `tunnel_insp_rule` | Same fix |

### Device Group Hierarchy (three naming patterns across log types)

All three DG Hierarchy naming patterns are handled by a single regex in
`_lookup_variable_names` — no config entries needed:

```
re.match(r"(?:Device Group Hierarchy(?:\s+Level)?|DG Hierarchy Level)\s+(\d+)", token)
```

| Pattern in format string | Example | Variable Name |
|---|---|---|
| `Device Group Hierarchy Level N` | "Device Group Hierarchy Level 1" | `dg_hier_level_1` |
| `DG Hierarchy Level N` | "DG Hierarchy Level 1" | `dg_hier_level_1` |
| `Device Group Hierarchy N` | "Device Group Hierarchy 1" | `dg_hier_level_1` |

### Global field name lookup corrections

These correct field table lookup keys that only need renaming for specific log types where the
table key is NEVER the correct format token for any log type. Entries where the table key IS the
correct format token for some log type cannot be global — they are handled per_log_type instead.

| Field Name lookup (in table) | Format string token | Variable Name | Log Type | Notes |
|---|---|---|---|---|
| Threat/Content Name | "Threat ID" | `threatid` | Data_Filtering_Log, Threat_Log, URL_Filtering_Log | Table name differs from format token |
| Certificate Fingerprint | "Fingerprint" | `fingerprint` | Decryption_Log | Table name differs from format token |
| Gateway Priority | "Priority" | `priority` | GlobalProtect_Log | Table name differs from format token |
| Gateway Name | "Gateway" | `gateway` | GlobalProtect_Log | Table name differs from format token |
| Gateway Selection Method | "Selection Type" | `selection_type` | GlobalProtect_Log | Table name differs from format token |
| SSL Response Time | "Response Time" | `response_time` | GlobalProtect_Log | Table name differs from format token |
| IPv6 System Address | "IPv6 Source Address" | `srcipv6` | HIP_Match_Log | Table name differs from format token |
| Threat/ContentType | "Threat/Content Type" | `subtype` | Decryption_Log | Typo in PA docs: missing space in table key |
| Issuer Common Name | "Issuer Subject Common Name" | `issuer_cn` | Decryption_Log | Table name differs from format token |
| Root Common Name | "Root Subject Common Name" | `root_cn` | Decryption_Log | Table name differs from format token |
| End IP Address | "End User IP Address" | `end_ip_adr` | GTP_Log | Table name differs from format token |
| Serving Network MCC | "Serving Country MCC" | `mcc` | GTP_Log | Table name differs from format token |
| Strict Checking | "Strict Check" | `strict_check` | Tunnel_Inspection_Log | Table name differs from format token |
| Security Rule UUID | "Rule UUID" | `rule_uuid` | Data_Filtering_Log, Threat_Log, Traffic_Log, Tunnel_Inspection_Log, URL_Filtering_Log | Table name differs from format token |
| Generate Time | "Generated Time" | `time_generated` | most log types | Table "Generate Time", format "Generated Time" (extra 'd'); lookup then returns variable name from parenthetical |
| Parent Session Start Time | "Parent Start Time" | `parent_start_time` | some log types | Table name differs from format token |

The following are NOT global because the table key IS the correct format token for some log types
(renaming globally would break those logs). They are handled by `field_name_lookup_corrections.per_log_type`
for the specific logs that use the different format token:

| Table key | "Other" format token (affected logs) | "Same as table" format token (other logs) | Handled by |
|---|---|---|---|
| Source Country | "Source Location" | "Source Country" (Traffic, URL, Data) | `per_log_type` (Threat, GTP, Tunnel_Inspection) |
| Destination Country | "Destination Location" | "Destination Country" (Traffic, URL, Data) | `per_log_type` (Threat, GTP, Tunnel_Inspection) |
| IP Protocol | "Protocol" | "IP Protocol" (Decryption) | `per_log_type` (Traffic, GTP, Tunnel_Inspection) |
| High Resolution Timestamp | "High Res Timestamp" | "High Resolution Timestamp" (most logs) | `per_log_type` (Decryption); `variable_name_corrections` (GlobalProtect — no table row for this field) |
| Threat/Content Type | "Subtype" | "Threat/Content Type" (Traffic, URL, Data, Audit) | `per_log_type` (Config, Tunnel_Inspection) |
| Tunnel Type | "Tunnel" | "Tunnel Type" (Traffic, GlobalProtect) | `per_log_type` (Decryption, Tunnel_Inspection) |
| Dynamic User Group Name | "Dynamic User Group" | "Dynamic User Group Name" (Traffic, etc.) | `per_log_type` (Tunnel_Inspection) |
| PCAP ID | "PCAP_ID" | "PCAP ID" (GTP, Tunnel_Inspection) | `per_log_type` (Threat, URL, Data) |

### Per-log-type field name lookup corrections

| Log Type | Field Name lookup (in table) | Format string token | Notes |
|---|---|---|---|
| IP_Tag_Log | "Serial Number" | "Serial" | Format string uses abbreviated token |
| IP_Tag_Log | "Generated Time" | "Generate Time" | IP_Tag table has "Generated Time", format uses "Generate Time" — per_log_type rename makes lookup succeed; parenthetical gives `time_generated` directly |
| Audit_Log | "Generate Time" | "Generate Time" | Identity mapping suppresses global's "Generate Time"→"Generated Time" rename; table key stays "Generate Time" so format token finds the (empty) row → placeholder pass-through → `variable_name_corrections` catches it |
| Threat_Log | "Source address" | "Source Address" | Field table lowercase 'a'; format uppercase 'A' |
| Threat_Log | "Destination address" | "Destination Address" | Same case mismatch |
| Threat_Log | "Source Country" | "Source Location" | Format "Source Location", table "Source Country" |
| Threat_Log | "Destination Country" | "Destination Location" | Format "Destination Location", table "Destination Country" |
| Threat_Log | "PCAP ID" | "PCAP_ID" | Format "PCAP_ID" (underscore), table "PCAP ID" (space) |
| URL_Filtering_Log | "Source address" | "Source Address" | Same case mismatch as Threat |
| URL_Filtering_Log | "Destination address" | "Destination Address" | Same case mismatch |
| URL_Filtering_Log | "PCAP ID" | "PCAP_ID" | Same as Threat |
| Data_Filtering_Log | "Source address" | "Source Address" | Same case mismatch as Threat |
| Data_Filtering_Log | "Destination address" | "Destination Address" | Same case mismatch |
| Data_Filtering_Log | "PCAP ID" | "PCAP_ID" | Same as Threat |
| Config_Log | "Threat/Content Type" | "Subtype" | Format "Subtype", table "Threat/Content Type" |
| Traffic_Log | "IP Protocol" | "Protocol" | Format "Protocol", table "IP Protocol" |
| GTP_Log | "Source Country" | "Source Location" | Same as Threat |
| GTP_Log | "Destination Country" | "Destination Location" | Same as Threat |
| GTP_Log | "IP Protocol" | "Protocol" | Same as Traffic |
| Decryption_Log | "High Resolution Timestamp" | "High Res Timestamp" | Format "High Res Timestamp", table "High Resolution Timestamp" |
| Decryption_Log | "Tunnel Type" | "Tunnel" | Format "Tunnel", table "Tunnel Type" |
| Tunnel_Inspection_Log | "Source Country" | "Source Location" | Same as Threat |
| Tunnel_Inspection_Log | "Destination Country" | "Destination Location" | Same as Threat |
| Tunnel_Inspection_Log | "IP Protocol" | "Protocol" | Same as Traffic |
| Tunnel_Inspection_Log | "Threat/Content Type" | "Subtype" | Same as Config |
| Tunnel_Inspection_Log | "Tunnel Type" | "Tunnel" | Same as Decryption |
| Tunnel_Inspection_Log | "Dynamic User Group Name" | "Dynamic User Group" | Format "Dynamic User Group", table "Dynamic User Group Name" |

---

## Layer 3 — Variable Name Corrections

Applied after `_lookup_variable_names`. Corrects variable names in both the format token
list and the `Variable Name` column of the field table. Global corrections use replace-all
semantics; per-log-type corrections use first-occurrence semantics on the token list.
Configured under `variable_name_corrections.global` and `per_log_type`.

### Lookup failures (raw long names that pass through unchanged)

When a format token has no matching row in the field table (or has a matching row with an
empty Variable Name that gets written back), the raw long name passes through to this stage:

| Token passed through | Variable Name | Log Type | Notes |
|---|---|---|---|
| "Generate Time" | `time_generated` | Audit_Log | Per_log_type identity `"Generate Time"→"Generate Time"` suppresses global rename; table key stays "Generate Time"; format token finds the row (empty Variable Name → placeholder pass-through → caught here). IP_Tag_Log now resolves via lookup (see Layer 2 per_log_type table). |
| "Parent Start Time" | `parent_start_time` | some log types | Safety fallback: field absent from some log type field tables even after global "Parent Session Start Time" correction |
| "High Res Timestamp" | `high_res_timestamp` | GlobalProtect_Log | GlobalProtect field table has no "High Resolution Timestamp" row at all — per_log_type correction cannot apply |
| "Source Mac Address" | `src_mac` | Traffic_Log, Authentication_Log, Decryption_Log | These format strings use mixed-case "Source Mac Address"; table key is all-caps "Source MAC Address" → lookup fails |
| "Destination Mac Address" | `dst_mac` | Traffic_Log, Decryption_Log | Same mixed-case mismatch as Source Mac Address |

The following were previously lookup failures but are now resolved by `field_name_lookup_corrections.per_log_type` —
lookup now succeeds and returns the correct variable name from the field table parenthetical directly:

| Token (was passed through) | Variable Name | Resolved by |
|---|---|---|
| "Generated Time" | `time_generated` | global: "Generate Time" → "Generated Time" renames table key; lookup succeeds |
| "Source Location" | `srcloc` | per_log_type (Threat/GTP/Tunnel_Inspection): "Source Country" → "Source Location" |
| "Destination Location" | `dstloc` | per_log_type (Threat/GTP/Tunnel_Inspection): "Destination Country" → "Destination Location" |
| "Protocol" | `proto` | per_log_type (Traffic/GTP/Tunnel_Inspection): "IP Protocol" → "Protocol" |
| "Subtype" | `subtype` | per_log_type (Config/Tunnel_Inspection): "Threat/Content Type" → "Subtype" |
| "Tunnel" | `tunnel` | per_log_type (Decryption/Tunnel_Inspection): "Tunnel Type" → "Tunnel" |
| "Dynamic User Group" | `dynusergroup_name` | per_log_type (Tunnel_Inspection): "Dynamic User Group Name" → "Dynamic User Group" |
| "PCAP_ID" | `pcap_id` | per_log_type (Threat/URL/Data): "PCAP ID" → "PCAP_ID" |
| "High Res Timestamp" | `high_res_timestamp` | per_log_type (Decryption): "High Resolution Timestamp" → "High Res Timestamp"; GlobalProtect still fails (no table row) |

**Note on Generate Time / Generated Time:** `field_name_lookup_corrections.global` renames the
table key "Generate Time" → "Generated Time". For most logs (where the format token IS "Generated
Time"), lookup now succeeds and returns `time_generated` from the parenthetical — no
`variable_name_corrections` entry needed for "Generated Time". Two exceptions handled per_log_type:
- **IP_Tag_Log**: format "Generate Time", table "Generated Time" (with 'd') — per_log_type renames
  IP_Tag's table key "Generated Time" → "Generate Time", so lookup of format token "Generate Time"
  succeeds and returns `time_generated` from the parenthetical directly. No variable_name_corrections
  entry needed for IP_Tag.
- **Audit_Log**: format "Generate Time", table "Generate Time" (no parenthetical) — per_log_type
  identity `"Generate Time"→"Generate Time"` overrides the global entry for this log type, suppressing
  the rename. Table key stays "Generate Time"; lookup of format token "Generate Time" finds the row
  (empty Variable Name → placeholder pass-through) → caught by `variable_name_corrections["Generate Time"]`.

**Note on Source/Destination MAC Address:** The format string uses different capitalization across
log types. Threat/URL/Data and most others use all-caps "Source MAC Address" — this matches the
table key exactly, so lookup succeeds and `src_mac` is returned from the parenthetical directly
(no correction needed). Traffic/Authentication/Decryption use mixed-case "Source Mac Address" —
this does NOT match the all-caps table key, so lookup fails and the token passes through to
`variable_name_corrections`.

### Field table Variable Name typos

PAN-OS field tables sometimes contain wrong or truncated variable names in the parenthetical.
These are corrected via `variable_name_corrections.global` after lookup:

| Log Type | Field Name | PAN-OS docs value | Correct variable name | Notes |
|---|---|---|---|---|
| User_ID_Log | FUTURE_USE | `FUTURE_USER` | `FUTURE_USE` | Typo in PAN-OS field table |
| IP_Tag_Log, Auth, URL, Threat, User-ID | High Resolution Timestamp | `high_res` | `high_res_timestamp` | Truncated in PA field table |
| IP_Tag_Log | Event ID | `event_id` | `eventid` | Underscore inconsistency |
| Traffic_Log | Tunnel ID/IMSI | `tunnelid/imsi` | `tunnel_id/imsi` | Missing underscore before slash |
| Tunnel_Inspection_Log | Tunnel ID | `tunnelid` | `tunnel_id/imsi` | Field table uses "Tunnel ID (tunnelid)" without /IMSI suffix |
| Tunnel_Inspection_Log | Monitor Tag | `monitortag` | `monitortag/imei` | Field table uses "Monitor Tag (monitortag)" without /IMEI suffix |
| GTP_Log | A Slice Service Type | `nsdsai_sst` | `nssai_sst` | "nsdsai" → "nssai" typo in PA docs |
| GTP_Log | A Slice Differentiator | `nsdsai_sd` | `nssai_sd` | Same typo |

For Tunnel_Inspection_Log, the format tokens "Tunnel ID/IMSI" and "Monitor Tag/IMEI" also
fail lookup (field table has "Tunnel ID" and "Monitor Tag" respectively as lookup keys),
so they pass through as raw long names and are caught by the same `variable_name_corrections`
entries (`"Tunnel ID/IMSI"` → `tunnel_id/imsi`, `"Monitor Tag/IMEI"` → `monitortag/imei`).

### Fields with no parenthetical in PA docs (pass-through + variable_name_corrections)

Some log types omit the parenthetical variable name from their field table. When
`_lookup_variable_names` finds a matching row with an empty Variable Name, it writes the
raw format token back to the Variable Name column as a placeholder and passes the token
through unchanged. The raw long name then reaches `variable_name_corrections.global`.

| Log Type | Field | Pass-through token | Corrected variable name |
|---|---|---|---|
| Audit_Log | Serial Number | "Serial Number" | `serial` |
| Audit_Log | Generate Time | "Generate Time" | `time_generated` — per_log_type identity mapping keeps table key as "Generate Time"; lookup finds the row (empty Variable Name → placeholder pass-through); caught by `variable_name_corrections["Generate Time"]` |
| Audit_Log | Event ID | "Event ID" | `eventid` |
| Audit_Log | Object | "Object" | `object` |
| Audit_Log | CLI Command | "CLI Command" | `cmd` |
| Audit_Log | Severity | "Severity" | `severity` |

The "Threat/Content Type" field in Audit_Log DOES have a parenthetical `(subtype)` and maps
correctly without any correction.

---

## Threat_Log — Swapped trailing fields (PAN-OS docs error, not yet corrected)

PAN-OS documentation lists the final two fields of the Threat Log format string in the
wrong order compared to URL Filtering and Data Filtering, which have identical schemas:

| Log Type | Documented trailing order | Correct order (from received logs) |
|---|---|---|
| Threat_Log | `..., Flow Type, Cluster Name` | `..., Cluster Name, Flow Type` |
| URL_Filtering_Log | `..., Cluster Name, Flow Type` | `..., Cluster Name, Flow Type` ✅ |
| Data_Filtering_Log | `..., Cluster Name, Flow Type` | `..., Cluster Name, Flow Type` ✅ |

The correct field order is `Cluster Name, Flow Type`, confirmed from actual received logs
and consistent with URL Filtering and Data Filtering. The PAN-OS Threat Log Fields
documentation page has `Flow Type` and `Cluster Name` transposed.

**Status:** documented but not yet corrected in PALOS. The current `Threat_format.csv`
line 2 reflects the erroneous documented order (`flow_type, cluster_name`). A future
`per_log_corrections` entry with `match: "flow_type"` swapping positions with `cluster_name`
would fix this without modifying the scraper logic.
