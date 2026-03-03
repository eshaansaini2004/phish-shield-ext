# PhishShield — Setup Guide

The extension works out of the box with heuristic checks (no setup needed).
The steps below unlock the full threat intelligence layer.

---

## Step 1 — Google Safe Browsing API Key

1. Go to https://console.cloud.google.com
2. Create a new project (or use an existing one)
3. In the search bar, search **"Safe Browsing API"** and click Enable
4. Go to **APIs & Services → Credentials → Create Credentials → API Key**
5. Copy the key — you'll need it in Step 3

---

## Step 2 — PhishTank API Key

1. Go to https://www.phishtank.com/register.php and create a free account
2. After logging in, go to https://www.phishtank.com/api_info.php
3. Request an API key (instant approval)
4. Copy the key

---

## Step 3 — Deploy the Cloudflare Worker

The worker is a lightweight proxy that keeps your API keys off the client.

### Prerequisites
```bash
npm install -g wrangler
```

### Deploy
```bash
cd cloudflare-worker
wrangler login        # opens browser, sign in with your Cloudflare account
wrangler deploy
```

After deploying, Wrangler will print your worker URL:
```
https://phishshield-api.YOUR_SUBDOMAIN.workers.dev
```

### Add your API keys as secrets (never committed to git)
```bash
wrangler secret put GOOGLE_SAFE_BROWSING_KEY
# paste your Google key when prompted

wrangler secret put PHISHTANK_API_KEY
# paste your PhishTank key when prompted
```

---

## Step 4 — Update the Worker URL in the extension

Open `src/background/api.js` and replace the placeholder:

```js
// Change this line:
const WORKER_URL = 'https://phishshield-api.workers.dev';

// To your actual worker URL:
const WORKER_URL = 'https://phishshield-api.YOUR_SUBDOMAIN.workers.dev';
```

Then rebuild:
```bash
npm run build
```

---

## Step 5 — Load the extension in Chrome

1. Run `npm run build` in the `phish-shield` folder
2. Open Chrome and go to `chrome://extensions`
3. Enable **Developer mode** (toggle, top right)
4. Click **Load unpacked**
5. Select the `dist/` folder inside `phish-shield`

To reload after code changes: click the refresh icon on the PhishShield card in `chrome://extensions`, then reload the webpage.

---

## ML Model (Planned)

The current system uses rule-based heuristics + Google Safe Browsing + PhishTank.

A TensorFlow.js phishing URL classifier trained on the UCI Phishing Dataset is planned as an additional layer. It will run entirely in-browser with no API calls required.

Status: in progress

---

## What works without any setup

- URL heuristic analysis (14 checks: IP URLs, brand spoofing, homoglyphs, suspicious TLDs, etc.)
- DOM/page content analysis (hidden iframes, fake alerts, form hijacking, etc.)
- Download interception (risky file types, MIME mismatch, auto-downloads)
- Hover tooltips and popup UI

What requires setup above: Google Safe Browsing database check, PhishTank phishing database check, domain age lookup.
