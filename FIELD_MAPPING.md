# Field Mapping Guide

PALOS maps scraped PAN-OS variable names to standard security schemas, enabling direct use of the output CSV datasets in SIEM ingestion pipelines, detection rules, and cross-source field normalization.

| Schema | Status | Output |
|--------|--------|--------|
| ECS (Elastic Common Schema) 9.3 | Active — 71/297 fields mapped | `{version}/ecs/panos_ecs_mapping.csv` |
| OCSF | Planned | `{version}/ocsf/` |

---

## ECS Mapping

### Output file

`11.1+/ecs/panos_ecs_mapping.csv` — one row per unique PAN-OS variable name, covering all 17 log types.

| Column | Description |
|--------|-------------|
| `Variable Name` | Normalized PAN-OS field identifier (e.g. `src`, `elapsed`, `tls_version`) |
| `Field Name` | Human-readable name from PA docs (e.g. `Source Address`) |
| `Log Types` | Comma-separated list of log types that contain this field |
| `PAN-OS Description` | Field description from PA documentation |
| `Mapping Type` | See notation below |
| `ECS Field` | ECS dotted path (e.g. `source.ip`) |
| `ECS Type` | ECS field type (e.g. `ip`, `keyword`, `long`) |
| `ECS Description` | ECS field description |

### Notation

**Mapping type:**
- `=` — direct 1:1 mapping; value is copied as-is to the ECS field
- `->` — derived or transformed; value is computed, converted, parsed, or aggregated

**Multiple ECS targets per PAN-OS field** use newline-within-cell encoding: each line in the `ECS Field`, `ECS Type`, `ECS Description`, and `Mapping Type` columns corresponds to one ECS target, in order.

**Example — `src`:**
```
Mapping Type:    =              =          =           ->
ECS Field:       source.address source.ip  related.ip  network.community_id
ECS Type:        keyword        ip         ip          keyword
```
- `source.address` (=): raw address string
- `source.ip` (=): typed IP field enabling range queries
- `related.ip` (=): contributes to the event-wide IP array
- `network.community_id` (->): derived from the full 5-tuple (src, dst, proto, sport, dport)

**Example — `proto`:**
```
Mapping Type:    =                  ->                    ->
ECS Field:       network.transport  network.iana_number   network.community_id
```

**Example — `user_agent`:**
```
Mapping Type:    =                     ->              ->                  ->              ->
ECS Field:       user_agent.original   user_agent.name user_agent.version  user_agent.os.name user_agent.os.version
```

### Coverage (ECS 9.3 / PAN-OS 11.1+)

- **297** unique variable names across 17 log types
- **71** mapped to ECS (~24%)
- **226** unmapped — see "Fields intentionally left unmapped" below

### Scripts

#### `generate_ecs_skeleton.py`

Rebuilds `panos_ecs_mapping.csv` from the current scraper output. Snapshots existing ECS mappings before regenerating, then re-applies them — so no manual work is lost.

**When to run:**
- After scraping a new PAN-OS version
- After applying variable name corrections that change field names (e.g. the `high_res_timestamp` fix)

```bash
python3 generate_ecs_skeleton.py
```

### Extending the mapping manually

1. Open `11.1+/ecs/panos_ecs_mapping.csv`
2. Find rows with an empty `ECS Field` column (unmapped fields)
3. Fill in `Mapping Type` (`=` or `->`), `ECS Field`, `ECS Type`, `ECS Description`
4. For multiple ECS targets: add additional lines within the cell (newline-separated), keeping all four ECS columns aligned line-by-line
5. Commit the updated CSV

### Fields intentionally left unmapped

**PAN-OS-specific — no ECS equivalent:**
- Virtual system hierarchy: `vsys`, `vsys_id`, `vsys_name`, `dg_hier_level_1–4`, `dg_id`
- Infrastructure: `cluster_name`, `logset`, `actionflags`, `repeatcnt`, `policy_id`, `policy_name`
- App-ID classification: `category_of_app`, `subcategory_of_app`, `technology_of_app`, `risk_of_app`, `characteristic_of_app`, `container_of_app`, `is_saas_of_app`, `sanctioned_state_of_app`
- SD-WAN: `sdwan_cluster`, `sdwan_cluster_type`, `sdwan_device_type`, `sdwan_site`
- SCTP/Diameter: `assoc_id`, `sctp_*`, `diam_*`, `stream_id`, `verif_tag_*`
- 4G/5G telecom: `msisdn`, `apn`, `rat`, `imsi`, `imei`, `mcc`, `mnc`, `gtp_*`, `teid*`, `nssai_*`
- TCP performance metrics: `tcp_rtt_*`, `tcp_retransit_cnt_*`, `tcp_zero_window_cnt_*`, `total_n_ooseq_*`
- AI traffic: `ai_traffic`, `ai_fwd_error`

**Event classification — vocabulary mismatch with ECS:**
The following fields are not mapped because PAN-OS values don't align with ECS expected vocabularies (ECS `event.kind`, `event.category`, etc. have controlled value sets):
`type`, `subtype`, `action`, `severity`, `reason`, `session_end_reason`, `eventid`, `direction`, `status`, `category`

---

## OCSF Mapping

Planned. A placeholder directory exists at `11.1+/ocsf/`.

Will follow the same pattern as ECS mapping once the OCSF field catalog is integrated: a `panos_ocsf_mapping.csv` with the same per-row structure and `=`/`->` notation.
