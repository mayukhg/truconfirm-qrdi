# TruConfirm QRDI — KnowledgeBase App

A browser-based application for authoring, managing, and activating **Qualys Remote Detection Interface (QRDI)** custom vulnerability detection signatures — with AI-assisted generation, a mock scan execution backend, and a full lifecycle management UI.

---

## Quick Start

```
1. Double-click  start.bat          (Windows)
   ./start.sh                       (Mac / Linux)

2. Open browser  http://localhost:8080
```

Both the frontend and the mock backend start automatically. The browser opens on its own.

---

## Table of Contents

1. [What It Does](#what-it-does)
2. [Project Structure](#project-structure)
3. [Getting Started](#getting-started)
   - [Startup & Shutdown Scripts](#startup--shutdown-scripts)
   - [Manual Start](#manual-start)
   - [AI Feature Setup (optional)](#ai-feature-setup-optional)
4. [Feature Overview](#feature-overview)
5. [Mock Backend API](#mock-backend-api)
6. [QRDI JSON Schema Quick Reference](#qrdi-json-schema-quick-reference)
7. [Key Functions Reference](#key-functions-reference)
8. [Documentation](#documentation)

---

## What It Does

| Capability | Detail |
|---|---|
| **QRDI Signature Authoring** | Raw JSON editor with syntax highlighting, inline schema validation, and one-click templates |
| **AI-Assisted Generation** | Natural language → QRDI JSON via Claude API (`claude-opus-4-5`) or built-in 10-pattern smart fallback (no API key needed) |
| **AI Signature Improvement** | Rule-based patcher adds `on_error`, `timeout`, `on_missing`, `debug_level`, and `title` fields to existing signatures |
| **Lua Library Management** | Upload, edit, publish, download, and delete shared Lua function libraries (`qrdiuser_*` prefix enforced) |
| **Scan Profile Management** | Attach QRDI checks to scan profiles with per-scan enable/disable granularity |
| **Mock Scan Execution** | Backend simulates QRDI dialog execution per host, returns VULNERABLE / NOT VULNERABLE / ERROR findings |
| **Activation Wizard** | 3-step wizard: Review signature → Select scan profile → Confirm activation |
| **Finding Detail View** | Per-finding evidence, raw debug output (RESULT_DEBUG), and error log (RESULT_ERRORS) |
| **Overview Dashboard** | Live KPI cards, lifecycle board, severity distribution chart, and activity feed (backed by `/api/stats`) |
| **Telemetry** | Every key action (signature created, AI invoked, scan executed) is logged to `/api/telemetry` |

---

## Project Structure

```
TruCon_QRDI/
├── index.html          # App shell — three tab views + all modals
├── styles.css          # Dark-theme design system (CSS variables, all components)
├── app.js              # All state, rendering, modal, AI, and API-layer logic
│
├── backend/
│   ├── server.js       # Express + json-server with custom scan execution simulator
│   ├── db.json         # Persistent mock database (signatures, findings, scans, telemetry)
│   └── package.json    # Backend dependencies (json-server, cors, node-fetch)
│
├── start.bat           # Windows: start backend + frontend + open browser
├── stop.bat            # Windows: stop both servers
├── start.sh            # Mac/Linux: start backend + frontend + open browser
├── stop.sh             # Mac/Linux: stop both servers
│
├── README.md           # This file
└── Usage.md            # Step-by-step user guide
```

---

## Getting Started

### Prerequisites
- **Node.js 18+** — [nodejs.org](https://nodejs.org)
- **Python 3.x** — [python.org](https://python.org)

### Startup & Shutdown Scripts

| Script | Platform | What it does |
|---|---|---|
| `start.bat` | Windows | Installs deps (first run), starts backend on :3001, frontend on :8080, opens browser |
| `stop.bat` | Windows | Kills both servers by port |
| `start.sh` | Mac/Linux | Same as start.bat, saves PIDs to `.backend.pid` / `.frontend.pid` |
| `stop.sh` | Mac/Linux | Kills by PID file, falls back to `lsof` port kill |

**Windows:**
```
Double-click start.bat
Double-click stop.bat    ← to stop
```

**Mac / Linux:**
```bash
chmod +x start.sh stop.sh   # first time only
./start.sh
./stop.sh                    # to stop
```

### Manual Start

Open two terminal windows:

```bash
# Terminal 1 — Backend (mock database + scan executor)
cd backend
npm install        # first time only
node server.js     # runs on http://localhost:3001

# Terminal 2 — Frontend
python -m http.server 8080   # runs on http://localhost:8080
```

Then open **http://localhost:8080** in your browser.

### AI Feature Setup (optional)

The AI signature assistant works without an API key using the built-in smart fallback (covers XSS, SQL injection, open redirect, HTTP headers, IMAP, SMTP, SMB, FTP, SSH, generic HTTP).

To use the full `claude-opus-4-5` model:
1. Get an API key from [console.anthropic.com](https://console.anthropic.com)
2. In the app: open any QRDI vulnerability → **QRDI Definition** tab → click **✦ AI**
3. Paste the key and click **Save**

> The key is stored only in `sessionStorage` — cleared when the tab is closed.

---

## Feature Overview

### Overview Tab
Home screen with live KPI cards (Total / Active / Lua Libraries / Pending), lifecycle board (Author → Validate → Attach → Execute → Monitor), severity bar chart, and recent activity feed. Cards update from `/api/stats` when the backend is running.

### KnowledgeBase Tab
Central table of all custom QRDI checks with filtering, search, and quick actions (Info / Edit / Disable).

**Creating a new signature — 6 steps:**
1. Click **New ▾ → New QRDI Vulnerability**
2. Fill **General Info**: QID (410001–430000), title, detection type, severity, debug level
3. *(Optional)* Add CVE / vendor reference mappings
4. *(Optional)* Fill threat, impact, solution text
5. In **QRDI Definition**: use a template, write JSON manually, or use the AI assistant
6. Click **Validate** → **Save**

### Scan Tab
Manage scan profiles and their attached checks. When the backend is running, a **▶ Run Scan Now** button appears in each profile detail. Results populate the findings list in real-time.

### AI Assistant (inside QRDI Definition tab)
- **Generate New** — describe a detection in plain English → complete QRDI JSON
- **Improve Existing** — paste/load a signature → get a hardened version with change log
- **Confidence score** — 🟢 High / 🟡 Medium / 🔴 Low based on dialog completeness
- **Apply to Editor** — explicit button; AI never auto-overwrites the editor

### Activation Wizard
Launched from the ℹ Info modal → ⚡ Activate for Scan. Three steps: Review → Select Profile → Confirm. Sets status to Active and links the signature to the chosen scan profile.

---

## Mock Backend API

Backend runs on **http://localhost:3001**. All data is persisted to `backend/db.json`.

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/signatures` | List all QRDI signatures |
| POST | `/api/signatures` | Create a signature |
| PUT | `/api/signatures/:id` | Update a signature |
| DELETE | `/api/signatures/:id` | Delete a signature |
| GET | `/api/profiles` | List scan profiles |
| GET | `/api/findings` | All findings (supports `?profileId=` and `?qid=` filters) |
| POST | `/api/scan/run` | Simulate a scan — body: `{ profileId, qids[] }` |
| GET | `/api/scans` | Scan run history |
| GET | `/api/stats` | Live KPI summary for the dashboard |
| POST | `/api/telemetry` | Log a user event |

**Example — run a scan:**
```bash
curl -X POST http://localhost:3001/api/scan/run \
  -H "Content-Type: application/json" \
  -d '{"profileId":"sp1","qids":[410001,410003]}'
```

**Example — get findings for a profile:**
```bash
curl "http://localhost:3001/api/findings?profileId=sp1"
```

---

## QRDI JSON Schema Quick Reference

```json
{
  "detection_type": "http dialog",
  "api_version": 1,
  "trigger_type": "service",
  "title": "Example Detection",
  "debug_level": 0,
  "dialog": [
    { "transaction": "http get",  "object": "/path", "on_error": "stop", "timeout": 30000 },
    { "transaction": "process",   "mode": "regexp",  "match": "pattern", "on_missing": "stop" },
    { "transaction": "report",    "result": "Vulnerability confirmed" }
  ]
}
```

| Field | Values |
|---|---|
| `detection_type` | `"http dialog"` · `"tcp dialog"` |
| `api_version` | Always `1` |
| `trigger_type` | `"service"` · `"virtual host"` (HTTP) · `"port"` (TCP) |
| `debug_level` | `0` off · `100` start/end · `200` transactions · `300` variables · `400` full |
| `on_error` / `on_missing` | `"continue"` · `"stop"` · `"report"` · `{"action":"goto","label":"..."}` |
| QID range | 410001 – 430000 |

---

## Key Functions Reference

| Function | What it does |
|---|---|
| `renderAll()` | Re-renders table, filter panel, stats, and active tab |
| `switchTab(tab)` | Switches between overview / scan / kb tabs |
| `openNew()` | Opens the New QRDI Vulnerability modal |
| `saveQrdiVuln()` | Validates, saves to state, and syncs to backend API |
| `validateJson()` | Parses editor JSON and updates validity indicator |
| `toggleJsonPreview()` | Swaps raw textarea ↔ syntax-highlighted preview |
| `runAIGenerate()` | Entry point for AI generation (Claude API or fallback) |
| `callClaudeAPI(prompt)` | Calls `claude-opus-4-5` via Anthropic Messages API |
| `smartGenerateQRDI(prompt)` | Built-in fallback — 10 patterns, no API key needed |
| `improveExisting(json)` | Rule-based patcher for existing signatures |
| `applyAISignature()` | Copies AI output to editor and re-validates |
| `scoreConfidence(parsed)` | Returns `"high"` / `"med"` / `"low"` |
| `openActivate(id)` | Launches the 3-step activation wizard |
| `renderScanTab()` | Renders the scan profile list |
| `runScanAPI(profileId)` | Calls `POST /api/scan/run`, updates UI with results |
| `openFindingDetail(finding)` | Opens finding modal with evidence + debug |
| `renderDashboard()` | Populates Overview tab from live `/api/stats` |
| `logTelemetry(payload)` | POSTs an event to `/api/telemetry` |
| `probeBackend()` | Checks if backend is online on app load |

---

## Documentation

| File | Description |
|---|---|
| `README.md` | Project overview, setup, API reference |
| `Usage.md` | Step-by-step user guide for all features |
| `QRDI_AI_Feature_Documentation.docx` | Detailed AI feature technical documentation |
| `QRDI_Final_Validation_Report.docx` | Requirements coverage report (QRDI_Req.docx source of truth) |

---

*Built by Claude Code · TruConfirm QRDI Project · April 2026*
