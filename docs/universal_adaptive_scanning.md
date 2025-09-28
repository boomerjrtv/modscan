# Universal Adaptive Scanning Architecture

This document captures the high-level design and operational guidance for the
new target-agnostic ModScan pipeline. The system swaps brittle,
application-specific routines for an adaptive orchestration loop that works
against any HTTP(S) target without manual tuning.

## Core Components

1. **Playbook Registry (`modules/universal_playbook_registry.py`)**  
   Loads declarative playbooks from `playbooks/` and evaluates lightweight
   fingerprint rules. Playbooks never hardcode target quirks; instead they
   declare triggers such as “numeric identifier present” or “URL parameter
   detected”.

2. **Knowledge Index (`modules/universal_knowledge_index.py`)**  
   A SQLite FTS store that unifies public payload families, disclosed reports,
   and future ModScan run artifacts. Retrieval is language-model friendly and
   runs entirely on CPU. The index seeds itself from bundled data on first run.

3. **Adaptive Probe Planner (`modules/adaptive_probe_planner.py`)**  
   Derives endpoint context (tags, numeric identifiers, URL parameters), selects
   matching playbooks, retrieves knowledge snippets, and materialises concrete
   probe variants. The planner is deterministic and technology agnostic.

4. **Universal Probe Executor (`modules/universal_probe_executor.py`)**  
   Executes the generated variants with aiohttp, compares control vs mutation
   responses, and computes evidence scores based on status deltas, reflection,
   content divergence, timing, and SSRF indicators.

5. **Universal Scan Engine (`modules/universal_scan_engine.py`)**  
   High-level coordinator that plugs into `ParallelScannerOrchestrator`. It
   translates scored probe results into the canonical `VulnerabilityFinding`
   structure so ModScan’s existing storage / reporting pipeline continues to
   work without changes.

## Data Flow

```
Target URL → Context fingerprinting → Playbook matching → Knowledge retrieval →
Probe plan generation → Probe execution → Signal scoring → VulnerabilityFinding
```

## Configuration

The following keys were added to `config.json` / `config.example.json`:

```json
"playbooks": { "directory": "playbooks" },
"knowledge_index": {
  "db_path": "data/knowledge_index.db",
  "seed_dir": "."
},
"adaptive_scanner": { "probe_timeout": 12.0 }
```

- Update `playbooks.directory` if you relocate the YAML bundles.  
- `knowledge_index.db_path` can point to an alternate SQLite location (e.g.
  shared volume).  
- `seed_dir` controls where the engine looks for HackerOne / payload corpora.  
- `probe_timeout` sets the per-request timeout for adaptive probes.

`ParallelScannerOrchestrator.bulk_scan_targets` now defaults to queueing an
`adaptive` scan before the legacy comprehensive sweep. The orchestrator falls
back gracefully if the universal engine fails to initialise.

## Extending Playbooks

- Add new YAML files to `playbooks/`; the registry loads `*.yml`, `*.yaml`, or
  `*.json` bundles automatically.  
- Action templates currently support `numeric_offset`, `reflection_payloads`,
  and `ssrf_payloads`. Add new templates by extending
  `AdaptiveProbePlanner._materialize_variants`. Keep generators generic (e.g.
  “JWT tampering”, “header toggles”) rather than application-specific.

## Knowledge Base Roadmap

- Add labelled ModScan findings via `UniversalKnowledgeIndex.upsert_document`.  
- Extend `hydrate_default_corpus` to ingest additional open datasets (PortSwigger
  labs, OWASP references, etc.).  
- Swap the built-in BM25 retrieval for embeddings + reranking when GPU/API
  resources are available; the abstraction already isolates retrieval from the
  planner.

## GitHub Snapshot Guidance

1. Create a fresh repository on GitHub (e.g. `modscan-universal`).  
2. Link the local branch created for this work:
   ```bash
   git remote add origin git@github.com:<user>/modscan-universal.git
   git push --set-upstream origin feature/universal-orchestration
   ```
3. Use GitHub Projects or Issues to track playbook additions, knowledge base
   ingestion tasks, and evaluation metrics (Precision@5, false positives).

The repository already exposes a dedicated branch (`feature/universal-
orchestration`) for this architecture, so pushing upstream preserves the exact
state captured in this sprint.

## Next Steps

- Expand playbook coverage (e.g. auth bypass headers, GraphQL schema probing,
  JSON schema diffing).  
- Integrate the confidence engine to feed adaptive scores into the existing
  validation workflow.  
- Add an evaluation harness that replays historical targets and tracks detection
  precision across adaptive vs comprehensive modes.  
- Wire the planner to optional hosted LLMs (Gemini Flash, etc.) for explanation
  synthesis without affecting core planning.
