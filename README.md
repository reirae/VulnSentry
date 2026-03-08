# VulnSentry — Installation & Setup Guide
> ICT2214 Web Security | Group P2CG2

---

## Overview

VulnSentry is a passive web vulnerability intelligence tool made up of two components:

- **Backend server** (`server.py` + `scanner.py`) — runs locally on Kali Linux, fingerprints websites using WhatWeb and Wappalyzer, queries the NVD for CVEs, and searches a local GHDB copy for Google Dorks.
- **Chrome extension** — sends the current page URL to the backend and displays scan results in real time via a popup.

---

## Prerequisites

### System Requirements

| Requirement | Details |
|---|---|
| Operating System | Kali Linux (recommended) or any Debian-based Linux |
| Python | 3.8 or higher |
| Browser | Google Chrome (any recent version) |
| Internet | Required for NVD API queries during scanning |

### Required Files

Ensure all of the following are in the **same working directory** before starting:

| File / Folder | Description |
|---|---|
| `server.py` | Flask backend — handles scan requests and streams results |
| `scanner.py` | Core scanning logic — WhatWeb, Wappalyzer, NVD, GHDB |
| `ghdb.xml` | Local Google Hacking Database XML file |
| `VulnSentry/` | Chrome extension folder containing `manifest.json` |

---

## Part 1 — Backend Server Setup

### Step 1 — Install System Dependencies

Open a terminal and run:

```bash
sudo apt update && sudo apt install -y whatweb python3-pip
```

Verify WhatWeb installed correctly:

```bash
whatweb --version
```

---

### Step 2 — Install Python Dependencies

```bash
pip install flask flask-cors nvdlib python-Wappalyzer requests --break-system-packages
```

> **Note:** The `--break-system-packages` flag is required on Kali Linux / Debian 12+ where pip is restricted by default.

Verify everything installed correctly:

```bash
python3 -c "import flask, nvdlib, requests; from Wappalyzer import Wappalyzer; print('All OK')"
```

Expected output: `All OK`

---

### Step 3 — Set Up the GHDB File

The scanner expects `ghdb.xml` to be in the **same directory** as `server.py`. Confirm it is present:

```bash
ls -lh ghdb.xml
```

If the file is missing, copy it from the Exploit-DB package:

```bash
sudo apt install exploitdb
cp /opt/exploit-database/ghdb.xml .
```

> **Warning:** If you place `ghdb.xml` in a different location, update the `GHDB_PATH` variable at the top of `scanner.py` to match the correct path.

---

### Step 4 — Verify Project Structure

Your working directory should look like this before starting:

```
your-project/
├── server.py
├── scanner.py
├── ghdb.xml
└── VulnSentry/
    ├── manifest.json
    ├── popup.html
    ├── popup.js
    └── (other extension files)
```

---

### Step 5 — Start the Flask Server

Navigate to your project directory and start the server:

```bash
cd /path/to/your-project
python3 server.py
```

You should see:

```
 * Running on http://0.0.0.0:8000
 * Running on http://127.0.0.1:8000
```

> **Note:** Keep this terminal window open. The server must stay running for the Chrome extension to work. Press `Ctrl+C` to stop it.

To confirm the server is responding, open a second terminal and run:

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "http://example.com"}'
```

You should see SSE log events streaming back in the terminal.

---

## Part 2 — Chrome Extension Setup

### Step 1 — Open the Chrome Extensions Page

In Google Chrome, navigate to:

```
chrome://extensions
```

Or go to: **Chrome Menu (⋮) → More Tools → Extensions**

---

### Step 2 — Enable Developer Mode

In the **top-right corner** of the Extensions page, toggle on **Developer mode**.

```
chrome://extensions  →  top-right corner  →  Developer mode  [ON]
```

> **Warning:** Developer mode must remain enabled for the extension to function. Disabling it will deactivate VulnSentry.

---

### Step 3 — Load the Extension

1. Click the **"Load unpacked"** button that appears after enabling Developer mode.
2. In the folder selection dialog, navigate to and select the **`VulnSentry/`** folder — the folder that contains `manifest.json`.
3. Click **Select Folder**.

> **Note:** Select the entire `VulnSentry/` folder, not an individual file inside it.

---

### Step 4 — Confirm the Extension Loaded

After loading, the VulnSentry card should appear on the Extensions page. Verify:

- [ ] No error messages are shown on the extension card
- [ ] The toggle at the bottom-right of the card is **enabled (blue)**
- [ ] The VulnSentry icon appears in the Chrome toolbar

---

### Step 5 — Pin the Extension to the Toolbar

For quick access during scanning:

1. Click the **puzzle piece icon (🧩)** in the Chrome toolbar
2. Find **VulnSentry** in the list
3. Click the **pin icon** next to it

The VulnSentry icon will now be permanently visible in your toolbar.

---

## Part 3 — Running Your First Scan

### Step 1 — Ensure the Backend is Running

Confirm `python3 server.py` is running and the Flask server is listening on port `8000`.

### Step 2 — Navigate to a Target Website

In Chrome, go to the website you want to scan. For example:

```
http://testhtml5.vulnweb.com
```

> **Warning:** Only scan websites you have explicit permission to test. VulnSentry is for authorised security testing only.

### Step 3 — Open VulnSentry

Click the **VulnSentry icon** in the Chrome toolbar. The popup will open and automatically begin scanning the current page URL.

The log panel will stream live output as the backend:
- Fingerprints the site with WhatWeb and Wappalyzer
- Queries the NVD for CVEs matched to detected versions
- Searches the local GHDB for relevant Google Dorks

### Step 4 — Review the Results

Once the scan completes, each detected technology is shown with:

- Technology name and detected version
- Source scanner(s) — WhatWeb, Wappalyzer, or both
- List of matched CVEs with NVD links and descriptions
- GHDB dorks — `[STRICT]` (version-specific) or `[GENERIC]` (fallback) — with clickable Google search links

---

## Troubleshooting

| Problem | Fix |
|---|---|
| Extension shows "Cannot connect to server" | Ensure `python3 server.py` is running on port `8000`. Check for firewall rules blocking `localhost:8000`. |
| `WhatWeb not installed` in logs | Run: `sudo apt install whatweb` |
| "No technologies detected" | The site may block scanners or return minimal headers. Try a different target URL. |
| NVD queries are very slow | The NVD API throttles unauthenticated requests. Add your NVD API key to `fetch_cves()` in `scanner.py` using the `apiKey` parameter. |
| GHDB only shows `[GENERIC]` dorks | The GHDB may not have version-specific entries for that technology. Generic dorks are still valid reconnaissance starting points. |
| Extension not appearing in toolbar | Click the puzzle piece icon (🧩) and pin VulnSentry manually. |
| `ghdb.xml not found` error | Ensure `ghdb.xml` is in the same folder as `server.py`, or update `GHDB_PATH` in `scanner.py` to the correct path. |
| `ModuleNotFoundError` on startup | Re-run the pip install command in Step 2 of Part 1 and ensure `--break-system-packages` is included. |

---

## Quick Reference

| Action | Command |
|---|---|
| Start the backend server | `python3 server.py` |
| Install Python packages | `pip install flask flask-cors nvdlib python-Wappalyzer requests --break-system-packages` |
| Install WhatWeb | `sudo apt install whatweb` |
| Install Exploit-DB (for GHDB) | `sudo apt install exploitdb` |
| Copy GHDB to project folder | `cp /opt/exploit-database/ghdb.xml .` |
| Test server endpoint | `curl -X POST http://localhost:8000/scan -H "Content-Type: application/json" -d '{"url":"http://example.com"}'` |
| Verify Python imports | `python3 -c "import flask, nvdlib, requests; from Wappalyzer import Wappalyzer; print('All OK')"` |
