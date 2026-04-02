# TruConfirm QRDI — Step-by-Step Usage Guide

> **Prerequisites:** Node.js 18+ and Python 3.x installed. Run `start.bat` (Windows) or `start.sh` (Mac/Linux) before opening the app.

---

## Quick Start

```
1. Double-click  start.bat          ← starts backend + frontend
2. Open browser  http://localhost:8080
3. Done — the app loads with pre-seeded QRDI data
```

---

## Section 1 — Starting and Stopping the App

### 1.1 Start (Windows)
```
Double-click:  start.bat
```
Two terminal windows open:
- **Backend** — `http://localhost:3001/api` (mock database + scan executor)
- **Frontend** — `http://localhost:8080` (the app UI)

Open your browser and go to: **http://localhost:8080**

### 1.2 Start (Mac / Linux)
```bash
chmod +x start.sh   # first time only
./start.sh
```

### 1.3 Stop
```
Double-click:  stop.bat          (Windows)
./stop.sh                        (Mac/Linux)
```
Both servers are terminated gracefully.

### 1.4 Manual start (if scripts don't work)
Open **two terminal windows** and run one command in each:

**Terminal 1 — Backend:**
```bash
cd backend
node server.js
```

**Terminal 2 — Frontend:**
```bash
python -m http.server 8080
```

---

## Section 2 — Navigating the App

The app has **three tabs** at the top:

| Tab | Purpose |
|---|---|
| **Overview** | Dashboard — KPI cards, lifecycle board, severity chart, activity feed |
| **Scan** | Manage scan profiles and run mock scans |
| **KnowledgeBase** | Create, edit, and manage QRDI vulnerability signatures |

Click any tab to switch views. The active tab is highlighted in blue.

---

## Section 3 — Overview Dashboard

The **Overview** tab loads automatically when you open the app.

### What you see
- **KPI Cards** (top row): Total QRDI Checks · Active · Lua Libraries · Pending Activation
- **Lifecycle Board**: How many signatures are at each stage (Author → Validate → Attach → Execute → Monitor)
- **Severity Distribution**: Bar chart showing Critical / High / Medium / Low counts
- **Recent Activity**: Last 5 actions with timestamps

### When the backend is running
KPI cards update live from `/api/stats` — counts reflect the actual database, not just in-memory data.

---

## Section 4 — KnowledgeBase Tab

### 4.1 Viewing signatures
1. Click the **KnowledgeBase** tab
2. The table shows all custom QRDI vulnerability checks
3. Each row shows: QID · Title · Severity badge · QRDI badge · Detection Type · Debug level · Status

### 4.2 Filtering the list
Use the **left filter panel**:
- **Category** — tick QRDI to show only custom checks
- **QVSS Base Score** — drag the slider to filter by risk score
- **Exploitability** — filter by Actively Exploited / Easy Exploit / POC Exploit

Use the **search bar** (top of table) to search by QID, title, or CVE ID. Results filter live as you type.

### 4.3 Viewing a signature's details
Click the **ℹ (Info)** icon on any row.

The Info modal shows:
- Full vulnerability metadata (QID, title, severity, CVE)
- A **lifecycle stepper** showing the current stage
- An **⚡ Activate for Scan** button (QRDI entries only)

### 4.4 Editing a signature
Click the **✎ (Edit)** icon on any row. The full 6-tab edit modal opens pre-populated with all existing data.

### 4.5 Disabling / Enabling a signature
Click the **⊖ / ⊕** icon on any row to toggle the global enabled state. Disabled signatures are greyed out and skipped during scan execution.

---

## Section 5 — Creating a New QRDI Signature

### Step 1 — Open the New modal
Click **New ▾** button (left side, below the search bar) → select **New QRDI Vulnerability**

### Step 2 — General Info tab
Fill in:
- **QID** — must be in the range 410001–430000 (unique per entry)
- **Title** — descriptive name for the detection
- **Detection Type** — click **HTTP Dialog** or **TCP Dialog**
- **Severity** — Critical / High / Medium / Low
- **CVSS Score** — 0.0 to 10.0
- **Debug Level** — select 0 (off) through 400 (full verbose)
- **Status** — Active / Draft / Disabled

### Step 3 — Additional Mappings tab *(optional)*
- Enter **CVE ID** and/or **Bugtraq ID**
- Click **+ Add Vendor Reference** to add external reference URLs

### Step 4 — Threat / Impact / Solution tabs *(optional)*
Type free-text descriptions for threat context, impact assessment, and remediation steps.

### Step 5 — QRDI Definition tab
This is where you define the actual detection logic.

**Option A — Use a Template (fastest)**
Click one of the four template buttons:
- **XSS Check** — HTTP GET with XSS payload reflection test
- **HTTP Header** — extracts Server version header
- **IMAP Auth** — TCP LOGIN command test
- **SMB Version** — SMB protocol negotiation via Lua

The JSON editor populates instantly. Review and adjust fields as needed.

**Option B — Write manually**
Type or paste valid QRDI JSON directly into the editor. Click **Validate** to check the structure.

**Option C — Use AI (see Section 6)**

### Step 6 — Validate and Save
1. Click **Validate** — a green ✓ Valid indicator must appear
2. Click **Save** — the signature appears in the KnowledgeBase table

---

## Section 6 — AI-Assisted Signature Creation

The AI assistant is inside the **QRDI Definition** tab of any New or Edit modal.

### 6.1 Open the AI panel
Click the **✦ AI** button in the JSON editor toolbar. The panel slides open below the editor.

### 6.2 Set up the API key *(optional — skip if using fallback)*
1. Get a key from [console.anthropic.com](https://console.anthropic.com)
2. Paste it in the **API Key** field
3. Click **Save** — the status dot turns green

> Without a key, the built-in smart fallback engine handles 10 common patterns automatically.

### 6.3 Generate a new signature
1. Make sure **Generate New** tab is selected (default)
2. Type a description — e.g. *"detect SQL error messages in HTTP responses"*
   - Or click one of the 6 **hint chips** to auto-fill a common prompt
3. Click **✦ Generate Signature**
4. The output panel shows:
   - Generated QRDI JSON
   - Explanation of each transaction step
   - Confidence indicator (🟢 High / 🟡 Medium / 🔴 Low)
5. Click **Apply to Editor** to copy the JSON into the editor

### 6.4 Improve an existing signature
1. Make sure the JSON editor already contains a signature (use a template or type one)
2. Click **Improve Existing** tab
3. *(Optional)* Type what to improve — e.g. *"add better error handling"*
   - Or leave blank for auto-analysis
   - Or click a hint chip: Add timeout handling · Extract version into variable · etc.
4. Click **⟳ Improve Signature**
5. Review the changes listed in the explanation panel
6. Click **Apply to Editor**

### 6.5 Toggle syntax highlighting
Click **🎨 Highlight** in the editor toolbar to switch between:
- **Raw mode** — plain textarea you can edit directly
- **Highlight mode** — colour-coded view (keys=blue, strings=green, numbers=red)

> Click Highlight again to return to editable raw mode before making changes.

---

## Section 7 — Lua Library Management

The Lua Library stores shared Lua function files that QRDI signatures can call via `{"call":{"name":"qrdiuser_*"}}`.

### 7.1 Open the Lua Library
Click **New ▾** → **Lua Library**, or click the **Lua Library** button in the toolbar.

### 7.2 Add a new library file
1. Click **+ Upload Library**
2. Fill in:
   - **Name** — must start with `qrdiuser_`
   - **Description** — what functions it provides
   - **Status** — Published / Draft / Inactive
3. Paste the Lua source code into the editor
4. Click **Save**

### 7.3 Edit a library
Click **✎ Edit** on any library row. The editor opens with the current source.

### 7.4 Download a library
Click **↓ Download** — saves the `.lua` file to your Downloads folder.

### 7.5 Delete a library
Click **✕ Delete** → confirm in the dialog. Signatures referencing this library will fail at runtime if it is deleted.

> **Rule:** A library must have status **Published** for scan-time execution to succeed.

---

## Section 8 — Scan Tab

### 8.1 View scan profiles
1. Click the **Scan** tab
2. The left panel lists all scan profiles with their asset group and schedule
3. Click any profile to open its detail view on the right

### 8.2 Attach a QRDI check to a profile
1. In the profile detail view, click **+ Attach QRDI Check**
2. The Attach Selector modal opens showing all available signatures
3. Click a signature row to select it
4. Click **Attach** — the check appears in the profile's check list

### 8.3 Enable / disable a check per scan
Each attached check has its own toggle in the profile detail view. This is **independent** of the global enable/disable on the vulnerability:
- **Green toggle** — check runs during scans for this profile
- **Grey toggle** — check is skipped for this profile only (still active globally)

### 8.4 Detach a check from a profile
Click **Detach** next to any check in the profile detail. This does not delete the vulnerability — it only removes it from this profile.

### 8.5 Run a mock scan *(backend must be running)*
1. Open a scan profile
2. Click **▶ Run Scan Now** (appears at the top of the profile detail when the backend is online)
3. The scan executes all enabled attached checks against the profile's simulated asset pool
4. Results appear in the **Results** section below the check list:
   - 🔴 **VULNERABLE** — detection match found
   - ✅ **NOT VULNERABLE** — no match
   - ⚠ **ERROR** — connection timeout or execution failure

### 8.6 View a finding detail
Click **View Finding** on any VULNERABLE result row to open the Finding Detail modal:
- **Result** — the reported detection message
- **Evidence** — raw HTTP/TCP response data
- **Debug Output** — RESULT_DEBUG transaction log
- **Error Log** — RESULT_ERRORS if any

---

## Section 9 — Activation Wizard

The Activation Wizard links a validated signature to a scan profile in 3 steps.

### How to launch
- From the **Info modal**: click **⚡ Activate for Scan**
- From the **KnowledgeBase** table: click ℹ → ⚡ Activate for Scan

### Step 1 — Review
Confirms the signature is ready:
- Detection Type, QID, Trigger Type shown
- Debug Level shown
- JSON validity confirmed (must be ✓ Valid)

Click **Next →**

### Step 2 — Select Profile
A list of all scan profiles is shown with asset group and schedule.
Click the profile you want to attach this signature to.

Click **Next →**

### Step 3 — Confirm Activation
Summary shows: Signature name → Profile name.
Click **✔ Confirm & Activate**.

The signature status changes to **Active** and it appears in the selected profile's check list.

---

## Section 10 — API Endpoints (Backend Reference)

When the backend is running on `http://localhost:3001`, these endpoints are available:

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/signatures` | List all QRDI signatures |
| POST | `/api/signatures` | Create a new signature |
| PUT | `/api/signatures/:id` | Update a signature |
| DELETE | `/api/signatures/:id` | Delete a signature |
| GET | `/api/profiles` | List scan profiles |
| GET | `/api/findings` | List all findings |
| GET | `/api/findings?profileId=sp1` | Filter findings by profile |
| GET | `/api/findings?qid=410001` | Filter findings by QID |
| POST | `/api/scan/run` | Execute a mock scan |
| GET | `/api/stats` | Dashboard KPIs + telemetry summary |
| POST | `/api/telemetry` | Log a user event |
| GET | `/api/scans` | Scan run history |

### Example: Run a scan via curl
```bash
curl -X POST http://localhost:3001/api/scan/run \
  -H "Content-Type: application/json" \
  -d '{"profileId":"sp1","qids":[410001,410003]}'
```

### Example: Get all findings for a profile
```bash
curl http://localhost:3001/api/findings?profileId=sp1
```

---

## Troubleshooting

| Problem | Fix |
|---|---|
| App shows blank page | Open `http://localhost:8080` — don't open `index.html` directly via file:// |
| Backend toast doesn't appear | Run `start.bat` first, then refresh the browser |
| AI feature gives CORS error | Make sure you're on `http://localhost:8080`, not `file://` |
| "▶ Run Scan Now" button missing | Backend is offline — run `start.bat` and refresh |
| QID validation error | QID must be between 410001 and 430000 and not already in use |
| JSON editor shows ✗ invalid | Check that `detection_type`, `api_version`, and `dialog` fields are present |
| Port 8080 already in use | Edit `start.bat` and change `8080` to any free port (e.g. `8090`) |
| Port 3001 already in use | Edit `backend/server.js` line 1 and change `PORT = 3001` to a free port |
