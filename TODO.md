# PhishShield — TODO

## In Progress

- [ ] **TensorFlow.js ML classifier (Layer 1 enhancement)**
  - Train or source a pre-trained phishing URL classifier from HuggingFace (UCI Phishing Dataset)
  - Convert to TensorFlow.js format
  - Bundle into the extension (runs fully in-browser, no API needed)
  - Feed URL features (length, entropy, subdomain count, TLD risk, etc.) as input vector
  - Blend ML score with existing heuristic score for final result
  - Target: ~95% accuracy on known phishing URLs

## Backlog

- [ ] **Canvas-based app support (Google Docs, Figma, Notion)**
  - These apps don't use standard `<a href>` tags so hover tooltips don't work
  - Option: intercept navigation via `chrome.webNavigation` and warn *after* click instead of before
  - Option: monitor `chrome.tabs.onUpdated` and run full URL analysis on every new page load
  - At minimum: show a warning banner if user lands on a flagged domain

- [ ] Set up Google Safe Browsing API key + deploy Cloudflare Worker
- [ ] Set up PhishTank API key
- [ ] Test on real phishing URLs from PhishTank feed
- [ ] Add support for canvas-based apps (Google Docs, Figma) via navigation interception
- [ ] Add settings page (toggle layers on/off, whitelist domains)
- [ ] Add phishing report button in popup (submit to PhishTank)
- [ ] Publish to Chrome Web Store

## Done

- [x] Scaffold Chrome extension (Manifest V3, React, Vite)
- [x] Layer 1: Static URL analysis (14 heuristic checks)
- [x] Layer 2: DOM/page content analysis (10 checks)
- [x] Layer 3: Download interception (7 checks)
- [x] Cloudflare Worker backend (Google Safe Browsing + PhishTank + domain age)
- [x] React popup UI (risk badge, score bar, flag list, accessibility-first)
- [x] Content script hover tooltips
- [x] Service worker orchestrator
