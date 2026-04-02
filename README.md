# TruConfirm QRDI — KnowledgeBase App

A fully client-side web application that brings **Qualys Remote Detection Interface (QRDI)** custom vulnerability signature management into a TruConfirm-styled dark UI. No build step, no backend server — open `index.html` in any modern browser or serve the three files with any static file server.

---

## Table of Contents

1. [What It Does](#what-it-does)
2. [Getting Started](#getting-started)
3. [App Structure](#app-structure)
4. [Feature Guide](#feature-guide)
   - [Overview Dashboard](#1-overview-dashboard)
   - [KnowledgeBase](#2-knowledgebase)
   - [QRDI Vulnerability Modal](#3-qrdi-vulnerability-modal)
   - [AI-Assisted Signature Creation](#4-ai-assisted-signature-creation)
   - [Lua Library](#5-lua-library)
   - [Scan Tab](#6-scan-tab)
5. [QRDI JSON Schema Quick Reference](#qrdi-json-schema-quick-reference)
6. [File Reference](#file-reference)

---

## What It Does

TruConfirm QRDI lets security engineers **author, manage, and activate** custom QRDI vulnerability detection signatures without leaving the browser. Key capabilities:

| Capability | Detail |
|---|---|
| Author QRDI signatures | Raw JSON editor with syntax highlighting and inline validation |
| AI-assisted authoring | Natural language → QRDI JSON via Claude API or built-in smart fallback |
| Lua Library management | Upload, edit, publish, and download shared Lua function libraries |
| Scan profile management | Attach QRDI checks to scan profiles with per-scan enable/disable |
| Activation wizard | 3-step wizard to validate, attach, and activate a signature for scanning |
| Finding detail view | Evidence, raw debug output, and error log per detection result |
| Overview dashboard | KPI cards, lifecycle board, severity chart, and activity feed |

---

## Getting Started

### Option A — Open directly

```
Double-click index.html
```

> Some browsers restrict `fetch()` on `file://` URLs. If the AI feature shows a CORS error, use Option B.

### Option B — Local static server (recommended)

**Python:**
```bash
cd /path/to/TruCon_QRDI
python -m http.server 8080
# Open http://localhost:8080
```

**Node (npx):**
```bash
npx serve .
# Follow the URL printed in the terminal
```

### AI feature (optional)

The AI signature assistant works without any API key using the built-in smart fallback engine. To use the full Claude model:

1. Get an Anthropic API key from [console.anthropic.com](https://console.anthropic.com)
2. Open any QRDI vulnerability → go to the **QRDI Definition** tab → click **✦ AI**
3. Paste your key in the API Key row and click **Save**

The key is stored only in `sessionStorage` — it is cleared when the tab is closed.

---

## App Structure

```
TruCon_QRDI/
├── index.html      # Full app markup — three tab views + all modals
├── styles.css      # Dark-theme design system (CSS variables, all component styles)
└── app.js          # All state, data, rendering, and interaction logic
```

No dependencies. No npm. No bundler. Open and run.

---

## Feature Guide

### 1. Overview Dashboard

The **Overview** tab (home screen) shows a live summary of the QRDI signature estate.

| Widget | Description |
|---|---|
| KPI Cards | Total QRDI Checks · Active · Lua Libraries · Pending Activation |
| Lifecycle Board | Steps from Author → Validate → Attach → Execute → Monitor with counts at each stage |
| Severity Distribution | Horizontal bar chart — Critical / High / Medium / Low breakdown |
| Recent Activity | Feed of the last 5 actions (signature created, AI generated, validated, activated) |

---

### 2. KnowledgeBase

The **KnowledgeBase** tab is the central list of all custom vulnerability checks.

#### Filter panel (left)
- **Category** — QRDI, Lua Library
- **QVSS Base Score** — slider range
- **RTI** — Real-Time Intelligence flags
- **Exploitability** — Actively Exploited, Easy Exploit, POC Exploit

#### Toolbar
- **Search** — live filter across QID, title, CVE ID
- **New ▾** — dropdown to create a new QRDI Vulnerability or open the Lua Library
- **Columns / Export / Settings** — icon buttons (UI scaffold)

#### Table columns
`QID · Title · Severity · Category · Detection Type · Debug · Status · Actions`

- **QRDI** badge — purple label on any custom check
- **Debug** badge — amber label showing the configured debug level (100/200/300/400)
- **Actions** — ℹ Info · ✎ Edit · ⊖ Disable/Enable

---

### 3. QRDI Vulnerability Modal

Opened via **New → New QRDI Vulnerability** or the ✎ Edit action. Six vertical tabs:

| Tab | Fields |
|---|---|
| **General Info** | QID · Title · Detection Type · Severity · CVSS · Debug Level · Status |
| **Additional Mappings** | CVE ID · Bugtraq ID · Vendor References (dynamic rows with URL) |
| **Threat** | Threat description textarea |
| **Impact** | Impact description textarea |
| **Solution** | Solution / remediation textarea |
| **QRDI Definition** | JSON editor · Syntax highlight toggle · AI Assistant panel · Templates |

#### JSON Editor features
- **Validate** button — checks required fields (`detection_type`, `api_version`, `dialog`) before saving
- **🎨 Highlight** toggle — switches between raw textarea and colour-coded preview
- **Templates** — four one-click starters: XSS Check · HTTP Header · IMAP Auth · SMB Version

#### Lifecycle stepper (Info modal)
When viewing an existing QRDI vulnerability, a 5-step lifecycle bar shows the current stage:
`Author → Validate → Attach → Execute → Monitor`

The **⚡ Activate for Scan** button launches the Activation Wizard directly from this view.

---

### 4. AI-Assisted Signature Creation

Located inside the QRDI Definition tab. Click **✦ AI** to open.

#### Generate New mode
Describe the vulnerability in plain English. Example prompts:
- *"Detect XSS in login page"*
- *"Check SMB protocol version via TCP"*
- *"Grab the HTTP server banner and report the version"*
- *"Test IMAP authentication and capture the response"*

Six hint chips populate the textarea with one click.

#### Improve Existing mode
Switch to Improve mode when the editor already contains a signature. The assistant will:
- Add `on_error: "stop"` to HTTP/TCP transactions missing it
- Add `timeout: 30000` to HTTP transactions
- Add `on_missing: "stop"` to process transactions
- Add `debug_level: 100` when you ask for debug/logging
- Add a `title` field if missing

Five hint chips cover the most common improvement requests.

#### Confidence indicator
Every generated signature receives a score:
- 🟢 **High** — has report + process/receive + correct type + api_version 1
- 🟡 **Medium** — has report but missing structural elements
- 🔴 **Low** — missing report transaction

#### API key (optional)
Without a key the built-in smart fallback covers 10 detection patterns (XSS, SQL injection, open redirect, HTTP headers, IMAP, SMTP, SMB, FTP, SSH, generic HTTP). With a key, any natural language description is supported via `claude-opus-4-5`.

---

### 5. Lua Library

Accessed via **New → Lua Library** or the Lua Library button. Manages shared Lua function files used by QRDI signatures.

| Action | Description |
|---|---|
| Upload | Add a new `.lua` file — name, description, status (Published / Draft / Inactive) |
| Edit | Modify the Lua source code and metadata inline |
| Download | Save the `.lua` file locally |
| Delete | Remove after confirmation |

**Rules enforced:**
- Function names must be prefixed `qrdiuser_`
- File size limit: 1 MB
- Status must be `Published` for a signature to reference the library at scan time

---

### 6. Scan Tab

The **Scan** tab manages scan profiles and their attached QRDI checks.

#### Profile list (left panel)
Shows all scan profiles with asset group and schedule. Click a profile to open its detail view.

#### Profile detail (right panel)
- **Attached QRDI Checks** — list of all custom checks attached to this profile, each with a per-scan enable/disable toggle
- **Attach QRDI Check** — opens the Attach Selector to browse all available QRDI checks and link one to this profile
- **Detach** — removes a check from the profile (does not delete the vulnerability)
- **Results** — scan result rows showing detection status (VULNERABLE / NOT VULNERABLE / ERROR), timestamp, and host count
- **View Finding** — opens the Finding Detail modal for any vulnerable result

#### Finding Detail modal
- QID · Title · User-Defined badge
- Result message and raw evidence from the QRDI dialog response
- Debug output section (RESULT_DEBUG)
- Error log section (RESULT_ERRORS)

#### Activation Wizard
Launched from ⚡ Activate for Scan in the info modal or directly from a check row.

**Step 1 — Review** · Confirms detection type, QID, trigger type, debug level, and JSON validity
**Step 2 — Select Profile** · Pick from available scan profiles (asset group + schedule shown)
**Step 3 — Confirm** · Sets the signature to Active and associates it with the chosen profile

---

## QRDI JSON Schema Quick Reference

```json
{
  "detection_type": "http dialog",
  "api_version": 1,
  "trigger_type": "service",
  "title": "Example HTTP Detection",
  "debug_level": 0,
  "dialog": [
    {
      "transaction": "http get",
      "object": "/endpoint",
      "on_error": "stop"
    },
    {
      "transaction": "process",
      "mode": "regexp",
      "match": "vulnerable-pattern",
      "on_missing": "stop"
    },
    {
      "transaction": "report",
      "result": "Vulnerability confirmed"
    }
  ]
}
```

| Field | Values |
|---|---|
| `detection_type` | `"http dialog"` · `"tcp dialog"` |
| `api_version` | Always `1` |
| `trigger_type` | `"service"` · `"virtual host"` (HTTP) · `"port"` (TCP) |
| `debug_level` | `0` (off) · `100` (start/end) · `200` (transactions) · `300` (variables) · `400` (full) |
| `on_error` / `on_missing` | `"continue"` · `"stop"` · `"report"` · `{"action":"goto","label":"..."}` |
| QID range | 410001 – 430000 |

---

## File Reference

| File | Purpose |
|---|---|
| `index.html` | App shell, all tab views (`view-overview`, `view-scan`, `view-kb`), all modals |
| `styles.css` | CSS custom properties, dark theme, badge classes, modal layouts, AI panel styles, scan tab styles |
| `app.js` | `CVE_DATA`, `QRDI_DEFAULTS`, `SCAN_PROFILES` mock data · state object `S` · all render/modal/AI functions |

### Key functions in app.js

| Function | What it does |
|---|---|
| `renderAll()` | Re-renders table, filter panel, stats, and active tab |
| `switchTab(tab)` | Switches between overview / scan / kb tabs |
| `openNew()` | Opens the New QRDI Vulnerability modal |
| `openEdit(id)` | Opens the edit modal pre-populated with an existing entry |
| `saveQrdiVuln()` | Validates and saves a QRDI entry to state |
| `validateJson()` | Parses the JSON editor content and updates the validity indicator |
| `toggleJsonPreview()` | Swaps between raw textarea and syntax-highlighted preview |
| `runAIGenerate()` | Entry point for AI generation (API or fallback) |
| `callClaudeAPI(prompt)` | Calls `claude-opus-4-5` via Anthropic Messages API |
| `smartGenerateQRDI(prompt)` | Built-in fallback — 10 detection patterns, no API key needed |
| `improveExisting(json)` | Rule-based patcher for existing QRDI signatures |
| `applyAISignature()` | Copies AI output to the JSON editor and re-validates |
| `scoreConfidence(parsed)` | Returns `"high"` / `"med"` / `"low"` confidence rating |
| `openActivate(id)` | Launches the 3-step activation wizard |
| `renderScanTab()` | Renders the scan profile list |
| `openFindingDetail(finding)` | Opens the finding detail modal with evidence + debug |
| `renderDashboard()` | Populates the Overview tab KPI cards, lifecycle board, chart, activity feed |
| `openLuaLib()` | Opens the Lua Library management modal |

---

*Built by Claude Code · TruConfirm QRDI Project · April 2026*
