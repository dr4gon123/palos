# Field Naming Normalization Guide

Raw PAN-OS syslog fields — `src`, `dst`, `app`, `action`, `serial`, and 290+ more — are meaningful within Palo Alto's own ecosystem, but become opaque the moment logs land in a multi-source SIEM alongside firewall, endpoint, identity, and cloud telemetry. Field name normalization is the process of mapping vendor-specific field names to a shared schema, enabling cross-source correlation, unified detection rules, and consistent dashboards without per-source query rewrites.

PALOS targets two schemas:

**ECS (Elastic Common Schema)** is an open, vendor-neutral field naming standard maintained by Elastic. Critically, ECS is [converging](https://www.elastic.co/docs/reference/ecs/ecs-otel-alignment-overview) with OpenTelemetry (OTel), the CNCF standard for observability instrumentation. This convergence means that ECS-normalized fields will be natively compatible with the OTel ecosystem, giving ECS-aligned data a path into both security and observability pipelines under a single, fully open-source, industry-wide standard.

**OCSF (Open Cybersecurity Schema Framework)** is a vendor-neutral, open standard developed by a cross-industry consortium including AWS, Splunk, IBM, CrowdStrike, Palo Alto Networks, and others. OCSF defines a full event taxonomy with typed categories and classes

Together, ECS and OCSF cover the two dominant normalization approaches — field naming and event classification — that security teams are converging on.

PALOS maps PAN-OS variable names to both, enabling the output CSV datasets to feed directly into SIEM ingestion pipelines, detection rules, and cross-source normalization workflows.

| Schema | Status | Output |
|--------|--------|--------|
| ECS (Elastic Common Schema) | Active — 71/297 fields mapped | `{version}/ecs/panos_ecs_mapping.csv` |
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

### Coverage (PAN-OS 11.1+)

- **297** unique variable names across 17 log types
- **71** mapped to ECS (~24%)
- **226** unmapped — see "Fields intentionally left unmapped" below

### Scripts

#### `generate_ecs_skeleton.py`

Rebuilds `panos_ecs_mapping.csv` from the current scraper output. Snapshots existing ECS mappings before regenerating, then re-applies them — so no manual work is lost.

**When to run:**

- After scraping a new PAN-OS version
- After applying variable name corrections that change field names

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
- Infrastructure: `cluster_name`, `logset`, `actionflags`, `repeatcnt`
- App-ID classification: `category_of_app`, `subcategory_of_app`, `technology_of_app`, `risk_of_app`, `characteristic_of_app`, `container_of_app`, `is_saas_of_app`, `sanctioned_state_of_app`
- SD-WAN: `sdwan_cluster`, `sdwan_cluster_type`, `sdwan_device_type`, `sdwan_site`, `policy_id`
- SCTP/Diameter: `assoc_id`, `sctp_*`, `diam_*`, `stream_id`, `verif_tag_*`
- 4G/5G telecom: `msisdn`, `apn`, `rat`, `imsi`, `imei`, `mcc`, `mnc`, `gtp_*`, `teid*`, `nssai_*`
- TCP performance metrics: `tcp_rtt_*`, `tcp_retransit_cnt_*`, `tcp_zero_window_cnt_*`, `total_n_ooseq_*`
- AI traffic: `ai_traffic`, `ai_fwd_error`

Some other PAN-OS-specific fields

**Event classification — ECS controlled vocabularies:**

ECS `event.*` fields (`event.kind`, `event.category`, `event.type`, `event.outcome`) are not free-form strings — they follow a strict controlled-vocabulary specification defined in the [ECS category field values reference](https://www.elastic.co/docs/reference/ecs/ecs-category-field-values-reference). Each field accepts only a fixed set of prescribed values with precise semantics (e.g. `event.kind` must be one of `alert`, `enrichment`, `event`, `metric`, `pipeline_error`, `signal`, `state`).

PAN-OS fields like `type`, `subtype`, `action`, `reason`, and `session_end_reason` carry PAN-OS-specific semantics that don't translate cleanly to these prescribed value sets. While the [ECS guide for firewall events](https://www.elastic.co/docs/reference/ecs/ecs-using-categorization-fields#_firewall_blocking_a_network_connection) provides clear guidelines, *Traffic* is just one of PAN-OS's 17 log types, each with its own semantics and intent. Correctly populating ECS event fields requires interpreting that intent — understanding not just what the field value says, but what it means in context. This kind of per-log-type, interpretation-driven translation introduces an inherent bias and is outside the scope of PALOS's field-level schema documentation.

---

## OCSF Mapping

Planned. A placeholder directory exists at `11.1+/ocsf/`.

Will follow the same pattern as ECS mapping once the OCSF field catalog is integrated: a `panos_ocsf_mapping.csv` with the same per-row structure and `=`/`->` notation.
