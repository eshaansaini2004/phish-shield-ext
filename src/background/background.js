// PhishShield background service worker
// Orchestrates analysis layers and manages extension state

import { analyzeURL } from '../analysis/urlAnalysis.js';
import { setupDownloadListener } from '../analysis/downloadAnalysis.js';
import { fetchThreatAnalysis } from './api.js';
import { loadMLModel, predictPhishing } from '../analysis/mlAnalysis.js';

// Load ML model on service worker startup
loadMLModel();

const SETTINGS_KEY = 'phishshield_settings';
const DEFAULT_SETTINGS = {
  disableUrlAnalysis: false,
  disableML: false,
  disableDom: false,
  disableDownload: false,
  whitelist: [],
};

async function getSettings() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(SETTINGS_KEY, (data) => {
      resolve({ ...DEFAULT_SETTINGS, ...(data[SETTINGS_KEY] || {}) });
    });
  });
}

// Badge color thresholds
function setBadge(tabId, score) {
  const text = String(score);
  let color;
  if (score < 30) color = '#22c55e';
  else if (score < 70) color = '#f59e0b';
  else color = '#ef4444';

  chrome.action.setBadgeText({ text, tabId });
  chrome.action.setBadgeBackgroundColor({ color, tabId });
}

// Merge DOM analysis result into an existing URL result object (pure, no I/O)
function applyDomResult(existing, domResult) {
  const merged = { ...existing };
  // De-dup by name+message so identical flags don't stack, but distinct flags with
  // the same name (e.g. cross_domain_form on two different hosts) are preserved.
  const seen = new Set((existing.flags || []).map((f) => f.name + '\x00' + f.message));
  const newFlags = (domResult.flags || []).filter((f) => !seen.has(f.name + '\x00' + f.message));
  merged.flags = [...(existing.flags || []), ...newFlags];
  // Take the higher of the two scores; DOM is an independent signal, not additive
  merged.score = Math.min(100, Math.max(existing.score, domResult.score || 0));
  return merged;
}

// Handle messages from content script
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'ANALYZE_URL' && msg.url) {
    handleAnalyzeURL(msg.url, sender, msg.tabId);
    sendResponse({ status: 'started' });
  }

  if (msg.type === 'DOM_ANALYSIS' && sender.tab) {
    // Merge DOM flags/score into the main result entry so App.jsx sees them.
    // Race: DOM often arrives before handleAnalyzeURL finishes (async API call).
    // If no main result yet, stash under dom_pending: so handleAnalyzeURL picks it up.
    const { url, result: domResult } = msg;
    getSettings().then((settings) => {
      if (settings.disableDom) return;
      const domPendingKey = `dom_pending:${url}`;
      chrome.storage.local.get(url, (data) => {
        const existing = data[url];
        if (!existing) {
          chrome.storage.local.set({ [domPendingKey]: domResult });
          return;
        }
        chrome.storage.local.set({ [url]: applyDomResult(existing, domResult) });
      });
    });
  }

  if (msg.type === 'RUN_DOM_ANALYSIS' && sender.tab) {
    // Content script asking background to be aware it ran DOM analysis
    sendResponse({ status: 'ok' });
  }

  return false; // not using async sendResponse
});

async function handleAnalyzeURL(url, sender, fallbackTabId) {
  const tabId = sender.tab?.id ?? fallbackTabId;
  if (!tabId) return;

  const settings = await getSettings();

  // Whitelist check: return safe immediately if domain is trusted
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    if ((settings.whitelist || []).some((d) => hostname === d || hostname.endsWith(`.${d}`))) {
      const safeResult = { score: 0, flags: [], whitelisted: true };
      chrome.storage.local.set({ [url]: safeResult });
      setBadge(tabId, 0);
      chrome.tabs.sendMessage(tabId, { type: 'ANALYSIS_COMPLETE', url, result: safeResult }).catch(() => {});
      return;
    }
  } catch (_) { /* invalid URL, fall through */ }

  // Step 1: fast local URL analysis + ML score
  const urlResult = settings.disableUrlAnalysis
    ? { score: 0, flags: [] }
    : analyzeURL(url);

  if (!settings.disableML) {
    const mlScore = predictPhishing(url);
    if (mlScore !== null) {
      // Blend: 45% heuristic, 55% ML
      urlResult.score = Math.min(100, Math.round(urlResult.score * 0.45 + mlScore * 0.55));
      urlResult.mlScore = mlScore;
      if (mlScore >= 60) {
        urlResult.flags.push({
          name: 'ml_classifier',
          severity: mlScore >= 80 ? 'high' : 'medium',
          message: `Machine learning classifier flagged this URL as likely phishing (${mlScore}% confidence).`,
        });
      }
    }
  }

  // Send preliminary result immediately
  chrome.tabs.sendMessage(tabId, {
    type: 'ANALYSIS_PRELIMINARY',
    url,
    result: urlResult,
  }).catch(() => {}); // tab might have navigated away

  setBadge(tabId, urlResult.score);

  // Step 2: async API lookup
  const apiData = await fetchThreatAnalysis(url);

  // Step 3: merge results
  const merged = { ...urlResult };

  if (apiData) {
    let apiBoost = 0;
    if (apiData.safeBrowsing.isMalicious) {
      apiBoost = Math.max(apiBoost, 80);
      merged.flags.push({
        name: 'safe_browsing_hit',
        severity: 'high',
        message: 'This URL is flagged as malicious by Google Safe Browsing.',
      });
    }
    if (apiData.phishTank.isPhishing) {
      apiBoost = Math.max(apiBoost, 70);
      merged.flags.push({
        name: 'phishtank_hit',
        severity: 'high',
        message: 'This URL is listed in PhishTank as a known phishing site.',
      });
    }
    if (apiData.domainAge.isNew) {
      apiBoost = Math.max(apiBoost, 15);
      merged.flags.push({
        name: 'new_domain',
        severity: 'low',
        message: 'This domain was recently registered, which is common for phishing sites.',
      });
    }
    merged.score = Math.min(100, Math.max(urlResult.score, apiBoost));
    merged.apiData = apiData;
  }

  // Check if DOM analysis already arrived while we were awaiting the API call
  if (!settings.disableDom) {
    const domPendingKey = `dom_pending:${url}`;
    const stored = await chrome.storage.local.get(domPendingKey);
    const pendingDom = stored[domPendingKey];
    if (pendingDom) {
      Object.assign(merged, applyDomResult(merged, pendingDom));
      chrome.storage.local.remove(domPendingKey);
    }
  }

  // Store final result
  chrome.storage.local.set({ [url]: merged });

  // Send final result to content script
  chrome.tabs.sendMessage(tabId, {
    type: 'ANALYSIS_COMPLETE',
    url,
    result: merged,
  }).catch(() => {});

  setBadge(tabId, merged.score);
}

// Download listener: warn on dangerous files
setupDownloadListener(async (downloadId, result) => {
  const settings = await getSettings();
  if (settings.disableDownload) return;
  if (result.shouldBlock) {
    chrome.notifications.create(`dl-warn-${downloadId}`, {
      type: 'basic',
      iconUrl: 'icons/icon-128.png',
      title: 'PhishShield: Suspicious Download',
      message: `"${result.details.filename}" looks dangerous (score: ${result.score}). ${result.flags[0]?.message || ''}`,
      priority: 2,
    });
  }
});

// When a tab finishes loading, tell the content script to kick off
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'complete') {
    chrome.tabs.sendMessage(tabId, { type: 'PAGE_LOADED' }).catch(() => {});
  }
});

// Canvas-app navigation protection (Google Docs, Figma, Notion, etc.)
// These apps render links without <a href> tags so hover tooltips never fire.
// We intercept the actual navigation commit instead and run the full analysis pipeline.
chrome.webNavigation.onCommitted.addListener(async (details) => {
  // Top-level navigations only — ignore iframes
  if (details.frameId !== 0) return;

  const { url, tabId } = details;

  // Skip browser-internal URLs
  if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('about:')) return;

  const settings = await getSettings();

  // Whitelist check
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    if ((settings.whitelist || []).some((d) => hostname === d || hostname.endsWith(`.${d}`))) {
      const safeResult = { score: 0, flags: [], whitelisted: true };
      chrome.storage.local.set({ [url]: safeResult });
      setBadge(tabId, 0);
      return;
    }
  } catch (_) { /* invalid URL, fall through */ }

  // Run the same analysis pipeline used for hover
  const urlResult = settings.disableUrlAnalysis ? { score: 0, flags: [] } : analyzeURL(url);

  if (!settings.disableML) {
    const mlScore = predictPhishing(url);
    if (mlScore !== null) {
      urlResult.score = Math.min(100, Math.round(urlResult.score * 0.45 + mlScore * 0.55));
      urlResult.mlScore = mlScore;
      if (mlScore >= 60) {
        urlResult.flags.push({
          name: 'ml_classifier',
          severity: mlScore >= 80 ? 'high' : 'medium',
          message: `Machine learning classifier flagged this URL as likely phishing (${mlScore}% confidence).`,
        });
      }
    }
  }

  const apiData = await fetchThreatAnalysis(url);
  const merged = { ...urlResult };

  if (apiData) {
    let apiBoost = 0;
    if (apiData.safeBrowsing.isMalicious) {
      apiBoost = Math.max(apiBoost, 80);
      merged.flags.push({ name: 'safe_browsing_hit', severity: 'high', message: 'This URL is flagged as malicious by Google Safe Browsing.' });
    }
    if (apiData.phishTank.isPhishing) {
      apiBoost = Math.max(apiBoost, 70);
      merged.flags.push({ name: 'phishtank_hit', severity: 'high', message: 'This URL is listed in PhishTank as a known phishing site.' });
    }
    if (apiData.domainAge.isNew) {
      apiBoost = Math.max(apiBoost, 15);
      merged.flags.push({ name: 'new_domain', severity: 'low', message: 'This domain was recently registered, which is common for phishing sites.' });
    }
    merged.score = Math.min(100, Math.max(urlResult.score, apiBoost));
    merged.apiData = apiData;
  }

  // Check if DOM analysis already arrived while we were awaiting the API call
  if (!settings.disableDom) {
    const domPendingKeyNav = `dom_pending:${url}`;
    const storedNav = await chrome.storage.local.get(domPendingKeyNav);
    const pendingDomNav = storedNav[domPendingKeyNav];
    if (pendingDomNav) {
      Object.assign(merged, applyDomResult(merged, pendingDomNav));
      chrome.storage.local.remove(domPendingKeyNav);
    }
  }

  // Store result so the popup can display it
  chrome.storage.local.set({ [url]: merged });
  setBadge(tabId, merged.score);

  if (merged.score >= 70) {
    chrome.notifications.create(`nav-warn-${tabId}-${Date.now()}`, {
      type: 'basic',
      iconUrl: 'icons/icon-128.png',
      title: 'PhishShield: Suspicious Page',
      message: `This page looks suspicious (score: ${merged.score}). Proceed with caution.`,
      priority: 2,
    });
  }
});
