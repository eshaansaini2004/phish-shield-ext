# PhishShield

A Chrome extension that analyzes links in real time and warns you before you click something malicious. Built for everyone, but especially for people who didn't grow up with the internet.

Hover over any link — you get an instant green, yellow, or red badge. Fully configurable via the settings page if you want to tune which layers run or whitelist trusted domains.

---

## What it does

**Four layers of analysis run every time you hover a link:**

### Layer 1 — URL Heuristics (instant, no internet needed)
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

### Layer 2 — ML Classifier (instant, no internet needed)
A neural network (MLP: 18 inputs → 32 → 16 → 1) runs entirely in the browser — no server round-trip. It extracts 18 URL features (entropy, subdomain depth, digit density, TLD risk, etc.) and returns a phishing probability score. That score is blended with the heuristic score (45% heuristic + 55% ML) so the two layers reinforce each other. If the ML confidence hits 60%+, it adds an explicit flag in the popup.

The model is trained with scikit-learn and exported to a compact JSON weight file (~24 KB). To retrain: `cd train_model && python train.py`.

### Layer 3 — Page Analysis (runs after the page loads)
Inspects the page you're on for phishing indicators:
- Password fields on HTTP pages
- Forms that submit to a different domain
- Hidden iframes loading external content
- Fake virus/system alert dialogs
- Brand name in page title doesn't match the actual domain
- Right-click disabled (common on phishing pages)
- Meta refresh redirects

### Layer 4 — Download Interception
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

### Settings Page
Right-click the extension icon → **Options** to:
- Toggle any analysis layer on or off (URL heuristics, ML, DOM, Download)
- Add domains to a whitelist — whitelisted sites bypass all checks and return safe instantly
- Settings sync across your Chrome profile via `chrome.storage.sync`

### Report as Phishing
In the popup, a small **⚑ Report** button appears after analysis. Clicking it:
- Opens PhishTank's submission page in a new tab so you can report it to the community
- Logs the report locally (`phishshield_reports` in chrome.storage) for your own records

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
These apps don't use standard HTML `<a href>` links. They render everything on a canvas layer with custom click handlers, so the extension can't hook into individual links. Hover tooltips won't appear inside them.

However, the extension now detects every top-level navigation via `webNavigation.onCommitted` — so if navigating *to* a dangerous URL through one of these apps, you'll still get a notification banner if the score hits 70+.

Affected for tooltips only: Google Docs, Sheets, Slides, Figma, Notion (partial).

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
    mlAnalysis.js        # Layer 2 — in-browser MLP inference (18 features)
    domAnalysis.js       # Layer 3 — 10 DOM/page checks
    downloadAnalysis.js  # Layer 4 — 7 download checks
  background/
    background.js        # Service worker, orchestrates all layers
    api.js               # Cloudflare Worker API client
  content/
    content.js           # Hover tooltips, page analysis trigger
  popup/
    App.jsx              # Main popup UI (includes report button)
    RiskBadge.jsx        # Big green/yellow/red status badge
    ScoreBar.jsx         # Risk score 0–100 bar
    FlagList.jsx         # Plain-English list of what was flagged
    HelpSection.jsx      # Collapsible explainer for non-technical users
  options/
    App.jsx              # Settings page (layer toggles + whitelist)
    main.jsx             # React entry for options page
public/
  model/
    weights.json         # Trained MLP weights + scaler params (~24 KB)
cloudflare-worker/
  worker.js              # Backend proxy for threat intelligence APIs
train_model/
  train.py               # scikit-learn training script → exports weights.json
  requirements.txt       # pip deps (scikit-learn, pandas, numpy, requests)
```

---

## Tech stack

- Chrome Extension Manifest V3
- React + Vite (popup UI)
- scikit-learn MLP → weights exported to JSON, forward pass in pure JS (no inference library needed)
- Cloudflare Workers (serverless backend, free tier)
- Google Safe Browsing API v4
- PhishTank API
