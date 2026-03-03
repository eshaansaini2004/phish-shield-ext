// PhishShield content script
// Injected into all pages to scan links and DOM for phishing indicators
//
// NOTE: This script is built as IIFE (no ES module imports).
// DOM analysis runs inline since domAnalysis.js will be bundled by Vite.
// URL analysis is delegated to the background service worker via messaging.

// ---- Inline DOM analysis (bundled at build time) ----
import { analyzePage } from '../analysis/domAnalysis.js';

// ---- Tooltip management ----
const TOOLTIP_ID = '__phishshield_tooltip';

function getOrCreateTooltip() {
  let el = document.getElementById(TOOLTIP_ID);
  if (el) return el;

  el = document.createElement('div');
  el.id = TOOLTIP_ID;
  Object.assign(el.style, {
    position: 'fixed',
    zIndex: '999999',
    pointerEvents: 'none',
    padding: '4px 10px',
    borderRadius: '12px',
    fontSize: '14px',
    fontWeight: 'bold',
    fontFamily: 'system-ui, sans-serif',
    color: '#fff',
    background: '#6b7280',
    boxShadow: '0 2px 8px rgba(0,0,0,0.18)',
    maxWidth: '200px',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    display: 'none',
    transition: 'opacity 0.15s',
    opacity: '0',
  });
  document.body.appendChild(el);
  return el;
}

function showTooltip(text, color, x, y) {
  const tip = getOrCreateTooltip();
  tip.textContent = text;
  tip.style.background = color;
  tip.style.left = `${Math.min(x + 12, window.innerWidth - 210)}px`;
  tip.style.top = `${Math.max(y - 30, 4)}px`;
  tip.style.display = 'block';
  // force reflow then fade in
  tip.offsetHeight;
  tip.style.opacity = '1';
}

function hideTooltip() {
  const tip = document.getElementById(TOOLTIP_ID);
  if (tip) {
    tip.style.opacity = '0';
    tip.style.display = 'none';
  }
}

function scoreLabel(score) {
  if (score < 30) return 'Safe';
  if (score < 70) return 'Suspicious';
  return 'Dangerous';
}

function scoreColor(score) {
  if (score < 30) return '#22c55e';
  if (score < 70) return '#f59e0b';
  return '#ef4444';
}

// ---- Link hover analysis ----
const analysisCache = new Map();
let currentHref = null;

function onMouseOver(e) {
  const anchor = e.target.closest('a[href]');
  if (!anchor) return;

  const href = anchor.href;
  if (!href || href.startsWith('javascript:') || href.startsWith('#')) return;

  // Already showing for this link, just reposition
  if (href === currentHref) {
    const tip = document.getElementById(TOOLTIP_ID);
    if (tip && tip.style.display !== 'none') {
      tip.style.left = `${Math.min(e.clientX + 12, window.innerWidth - 210)}px`;
      tip.style.top = `${Math.max(e.clientY - 30, 4)}px`;
    }
    return;
  }

  currentHref = href;
  const cached = analysisCache.get(href);
  if (cached) {
    showTooltip(`${cached.score} — ${scoreLabel(cached.score)}`, scoreColor(cached.score), e.clientX, e.clientY);
    return;
  }

  showTooltip('Checking...', '#6b7280', e.clientX, e.clientY);
  chrome.runtime.sendMessage({ type: 'ANALYZE_URL', url: href });
}

function onMouseOut(e) {
  const anchor = e.target.closest('a[href]');
  if (!anchor) return;
  // Only hide if mouse truly left the anchor (not just moved to a child element)
  if (!anchor.contains(e.relatedTarget)) {
    currentHref = null;
    hideTooltip();
  }
}

// ---- Message listener from background ----
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === 'ANALYSIS_PRELIMINARY' || msg.type === 'ANALYSIS_COMPLETE') {
    const { url, result } = msg;
    analysisCache.set(url, result);

    // Update tooltip if it's currently visible
    const tip = document.getElementById(TOOLTIP_ID);
    if (tip && tip.style.display !== 'none') {
      showTooltip(
        `${result.score} - ${scoreLabel(result.score)}`,
        scoreColor(result.score),
        parseInt(tip.style.left) || 0,
        parseInt(tip.style.top) + 30 || 0,
      );
    }
  }

  if (msg.type === 'PAGE_LOADED') {
    runPageAnalysis();
  }
});

// ---- DOM analysis ----
function runPageAnalysis() {
  try {
    const result = analyzePage();
    chrome.runtime.sendMessage({
      type: 'DOM_ANALYSIS',
      url: location.href,
      result,
    });

    // Also request URL analysis for the current page
    chrome.runtime.sendMessage({ type: 'ANALYZE_URL', url: location.href });
  } catch (err) {
    console.warn('[PhishShield] DOM analysis error:', err.message);
  }
}

// ---- Init ----
function init() {
  // attach link hover listeners using delegation
  document.addEventListener('mouseover', onMouseOver);
  document.addEventListener('mouseout', onMouseOut);

  // run page analysis if DOM is already loaded
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', runPageAnalysis);
  } else {
    runPageAnalysis();
  }

  // Watch for dynamically added links (no action needed per-link since we use delegation)
  // But we re-analyze the page if significant DOM changes happen
  let debounceTimer = null;
  const observer = new MutationObserver(() => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      // re-scan for new DOM phishing indicators
      runPageAnalysis();
    }, 2000);
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
  });
}

init();
