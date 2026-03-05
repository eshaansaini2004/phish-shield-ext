// PhishShield background service worker
// Orchestrates analysis layers and manages extension state

import { analyzeURL } from '../analysis/urlAnalysis.js';
import { setupDownloadListener } from '../analysis/downloadAnalysis.js';
import { fetchThreatAnalysis } from './api.js';
import { loadMLModel, predictPhishing } from '../analysis/mlAnalysis.js';

// Load ML model on service worker startup
loadMLModel();

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

// Handle messages from content script
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'ANALYZE_URL' && msg.url) {
    handleAnalyzeURL(msg.url, sender);
    sendResponse({ status: 'started' });
  }

  if (msg.type === 'DOM_ANALYSIS' && sender.tab) {
    // Store DOM analysis results alongside URL results
    const key = `dom:${msg.url}`;
    chrome.storage.local.set({ [key]: msg.result });
  }

  if (msg.type === 'RUN_DOM_ANALYSIS' && sender.tab) {
    // Content script asking background to be aware it ran DOM analysis
    sendResponse({ status: 'ok' });
  }

  return false; // not using async sendResponse
});

async function handleAnalyzeURL(url, sender) {
  const tabId = sender.tab?.id;
  if (!tabId) return;

  // Step 1: fast local URL analysis + ML score
  const urlResult = analyzeURL(url);
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
setupDownloadListener((downloadId, result) => {
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
