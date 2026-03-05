// PhishShield ML inference
// Pure-JS forward pass on weights trained by train_model/train.py
// No dependencies. Must stay in sync with extract_features() in train.py.

const SUSPICIOUS_TLDS = new Set(['.xyz', '.top', '.club', '.work', '.gq', '.cf', '.tk', '.ml', '.ga', '.pw']);
const SUSPICIOUS_KW = ['login', 'secure', 'account', 'update', 'verify', 'banking', 'confirm', 'password', 'signin', 'webscr'];
const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly']);

function urlEntropy(s) {
  if (!s) return 0;
  const freq = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  const n = s.length;
  return -Object.values(freq).reduce((sum, f) => sum + (f / n) * Math.log2(f / n), 0);
}

// 18 features — must match extract_features() in train.py exactly
function extractFeatures(url) {
  try {
    const full = url.includes('://') ? url : 'http://' + url;
    const parsed = new URL(full);
    const hostname = parsed.hostname.toLowerCase();
    const path = parsed.pathname;
    const query = parsed.search.slice(1); // strip leading '?'
    const parts = hostname.split('.');
    const tld = '.' + parts[parts.length - 1];

    return [
      Math.min(url.length, 200) / 200,
      Math.min(hostname.length, 100) / 100,
      Math.min(parts.length - 1, 10) / 10,
      Math.min((hostname.match(/-/g) || []).length, 10) / 10,
      /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) ? 1 : 0,
      parsed.protocol === 'https:' ? 1 : 0,
      Math.min(Math.max(0, parts.length - 2), 5) / 5,
      SUSPICIOUS_TLDS.has(tld) ? 1 : 0,
      url.includes('@') ? 1 : 0,
      Math.min(urlEntropy(url), 6) / 6,
      Math.min(path.length, 100) / 100,
      Math.min((hostname.match(/\d/g) || []).length, 10) / 10,
      SUSPICIOUS_KW.some(kw => url.toLowerCase().includes(kw)) ? 1 : 0,
      Math.min((url.match(/\//g) || []).length, 10) / 10,
      /%[0-9a-fA-F]{2}/.test(hostname) ? 1 : 0,
      SHORTENERS.has(hostname) ? 1 : 0,
      Math.min(query ? query.split('&').length : 0, 5) / 5,
      /\.\w{2,4}\.\w{2,4}$/.test(path) ? 1 : 0,
    ];
  } catch {
    return new Array(18).fill(0);
  }
}

function relu(x) { return Math.max(0, x); }
function sigmoid(x) { return 1 / (1 + Math.exp(-x)); }

function denseForward(input, W, b, activation) {
  return b.map((bi, i) => activation(bi + input.reduce((s, xi, j) => s + xi * W[j][i], 0)));
}

let _model = null;

export async function loadMLModel() {
  if (_model) return;
  try {
    const res = await fetch(chrome.runtime.getURL('model/weights.json'));
    _model = await res.json();
    console.log('[PhishShield] ML model loaded');
  } catch (err) {
    console.warn('[PhishShield] ML model not available:', err.message);
  }
}

// Returns 0-100 phishing probability score, or null if model not loaded
export function predictPhishing(url) {
  if (!_model) return null;

  const raw = extractFeatures(url);

  // Apply StandardScaler (same as training)
  const scaled = raw.map((v, i) => (v - _model.scaler_mean[i]) / (_model.scaler_std[i] || 1));

  const layers = _model.layers;
  let h = scaled;
  for (let i = 0; i < layers.length - 1; i++) {
    h = denseForward(h, layers[i].W, layers[i].b, relu);
  }
  const last = layers[layers.length - 1];
  const prob = denseForward(h, last.W, last.b, sigmoid)[0];

  return Math.round(prob * 100);
}
