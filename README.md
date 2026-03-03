# PhishShield

A Chrome extension that analyzes links in real time and warns you before you click something malicious. Built for everyone, but especially for people who didn't grow up with the internet.

Hover over any link — you get an instant green, yellow, or red badge. No settings to configure, no accounts to create.

---

## What it does

**Three layers of analysis run every time you hover a link:**

### Layer 1 — URL Analysis (instant, no internet needed)
Checks the URL itself before anything loads:
- IP-based URLs (`http://192.168.1.1/login`)
- Brand impersonation in subdomains (`paypal.com.evil.com`)
- Brand misspellings (`paypa1.com`, `g00gle.com`)
- Unicode lookalike characters (е vs e, а vs a)
- Suspicious keywords (`/verify-account`, `/confirm-password`)
- URL shorteners (bit.ly, tinyurl, etc.)
- Sketchy TLDs (`.tk`, `.ml`, `.cf`, `.gq`)
- Double extensions (`invoice.pdf.exe`)
- Redirect chains (`?url=`, `?goto=`)
- And more (14 checks total)

### Layer 2 — Page Analysis (runs after the page loads)
Inspects the page you're on for phishing indicators:
- Password fields on HTTP pages
- Forms that submit to a different domain
- Hidden iframes loading external content
- Fake virus/system alert dialogs
- Brand name in page title doesn't match the actual domain
- Right-click disabled (common on phishing pages)
- Meta refresh redirects

### Layer 3 — Download Interception
Catches dangerous downloads before they run:
- High-risk file types (`.exe`, `.bat`, `.ps1`, `.vbs`, etc.)
- MIME type mismatch (file claims to be a PDF, is actually an .exe)
- Double extensions (`document.pdf.exe`)
- Auto-downloads not triggered by user click
- Generic phishing filenames (`invoice.exe`, `update.exe`)

### Threat Intelligence APIs (requires setup)
When configured, the extension also checks against:
- **Google Safe Browsing** — Google's database of known malicious URLs
- **PhishTank** — crowd-sourced phishing URL database
- **Domain age** — flags newly registered domains (common in phishing campaigns)

See [SETUP.md](./SETUP.md) for how to enable these.

---

## What it looks like

Hover over any link on any webpage — a small pill badge appears near your cursor:

- **Green** — looks safe
- **Yellow** — something suspicious, worth a second look
- **Red** — multiple red flags, don't click this

Click the extension icon in your toolbar to see the full breakdown: risk score, exactly what was flagged, and a plain-English explanation.

---

## Known limitations

### Google Docs, Figma, and similar apps
These apps don't use standard HTML `<a href>` links. They render everything on a canvas layer with custom click handlers, so the extension can't hook into individual links. The extension still runs page-level analysis (Layer 2) but hover tooltips won't appear.

Affected: Google Docs, Google Sheets, Google Slides, Figma, Notion (partial), and other canvas-based web apps.

Workaround tracked in [TODO.md](./TODO.md).

### iframes
Content inside cross-origin iframes (like embedded ads) isn't accessible to the content script due to browser security policies. Links inside those iframes won't get tooltips.

### URL shorteners
The extension flags known shortener domains (bit.ly, tinyurl, etc.) as suspicious since the real destination is hidden. It can't follow the redirect without the Cloudflare Worker deployed.

---

## Getting started

```bash
npm install
npm run build
```

Then in Chrome: `chrome://extensions` → Developer mode → Load unpacked → select `dist/`

For full setup including API keys: see [SETUP.md](./SETUP.md)

---

## Project structure

```
src/
  analysis/
    urlAnalysis.js       # Layer 1 — 14 URL heuristic checks
    domAnalysis.js       # Layer 2 — 10 DOM/page checks
    downloadAnalysis.js  # Layer 3 — 7 download checks
  background/
    background.js        # Service worker, orchestrates all layers
    api.js               # Cloudflare Worker API client
  content/
    content.js           # Hover tooltips, page analysis trigger
  popup/
    App.jsx              # Main popup UI
    RiskBadge.jsx        # Big green/yellow/red status badge
    ScoreBar.jsx         # Risk score 0–100 bar
    FlagList.jsx         # Plain-English list of what was flagged
    HelpSection.jsx      # Collapsible explainer for non-technical users
cloudflare-worker/
  worker.js              # Backend proxy for threat intelligence APIs
```

---

## Tech stack

- Chrome Extension Manifest V3
- React + Vite (popup UI)
- Cloudflare Workers (serverless backend, free tier)
- Google Safe Browsing API v4
- PhishTank API
