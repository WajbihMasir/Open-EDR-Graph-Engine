# Open-EDR Graph Engine — PRD

## Original Problem Statement
Build the UI MVP for "Open-EDR Graph Engine" (Wazuh & Sysmon): P0 = Process Graph Reconstruction Engine (Sysmon EID 1/3/11 → nodes + edges using ProcessGuid/ParentProcessGuid, ancestor/descendant traversal, artifact correlation SPAWNED / CONNECTED_TO / WROTE_FILE), REST API (GET /api/graph/{process_guid}, POST /api/investigations), Interactive Process Graph Canvas, then Process Inspector. Golden test case: Office → cmd → PowerShell → download → payload.

User choices: data source = UI focus (seeded golden dataset), P0 only, React Flow + dagre, no login.

## Architecture
- Backend (FastAPI + MongoDB): `graph_engine.py` (parser, GUID resolver, BFS traversal, artifact correlation, MITRE rules, severity), `seed_data.py` (golden dataset, 22 events, shuffled to simulate out-of-order arrival), `server.py` (routes).
- Collections: `sysmon_events` (raw Wazuh-like docs), `investigations`.
- API: GET /api/graph/{guid}?start_time&end_time, POST/GET /api/investigations, GET /api/search?q=, GET /api/events/summary, POST /api/events/ingest.
- Frontend: React + @xyflow/react + @dagrejs/dagre. Dark terminal-style UI (IBM Plex Mono/Sans, JetBrains Mono).

## Implemented (2026-06)
- Graph Builder MVP with ProcessGuid identity, ancestor + descendant traversal, network/file artifact correlation, time-window filter, metadata (counts, depth, build ms)
- Rule-based MITRE mapping + severity; base64 `-enc` decoding
- Canvas: custom process/network/file nodes, target highlight, TB/LR layout, minimap, legend
- Process Inspector (PID, GUID, parent link, command line + decoded, user, integrity, SHA256/MD5, MITRE, relations, pivot)
- Search (GUID/PID/image/command line), suggested targets, recent investigations, status bar
- Tested: backend 100%, frontend 100% (iteration_1)

## Backlog
- P1: Timeline scrubber (replay execution order); real Wazuh/OpenSearch connector; upload Sysmon JSON via UI
- P1: Orphan "Unknown Parent" placeholder nodes; noise pruning / collapse
- P2: Export PNG/PDF, case actions, VirusTotal hash lookup, migrate on_event → lifespan
