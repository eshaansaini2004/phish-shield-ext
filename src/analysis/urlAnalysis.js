// Layer 1: Static URL Analysis

import { MULTI_PART_TLDS, getTLD1 } from './domainUtils.js';

const BRANDS = [
  'google', 'paypal', 'amazon', 'facebook', 'apple', 'microsoft',
  'netflix', 'instagram', 'twitter', 'linkedin', 'chase',
  'bankofamerica', 'wellsfargo', 'citibank', 'ebay', 'dropbox',
  'yahoo', 'outlook', 'gmail'
];

const SUSPICIOUS_KEYWORDS = [
  'login', 'secure', 'account', 'update', 'verify', 'banking',
  'confirm', 'password', 'signin', 'webscr', 'ebayisapi'
];

const SHORTENER_DOMAINS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
  'buff.ly', 'short.link', 'tiny.cc', 'is.gd'
];

const SUSPICIOUS_TLDS = [
  '.xyz', '.top', '.club', '.work', '.gq', '.cf', '.tk', '.ml', '.ga', '.pw'
];

const REDIRECT_PARAMS = ['url', 'redirect', 'goto', 'link'];

// Registrable domains that legitimately contain a brand name as a compound.
// Without this allowlist, e.g. applepay.com would trigger deceptive_subdomain
// because 'apple' appears in the hostname but tld1 !== 'apple.<tld>'.
const BRAND_OWNED_COMPOUNDS = new Set([
  'applepay.com', 'googlemail.com', 'paypalobjects.com',
  'microsoft365.com', 'microsoftonline.com', 'amazonpay.com',
]);

// Tighter subset of SUSPICIOUS_KEYWORDS: action verbs only, used to gate brand_in_path.
// Broader list includes nouns like 'banking'/'password' that appear in docs and aren't
// strong enough signal on their own to flag a brand mention.
const HARVEST_ACTION_KEYWORDS = ['login', 'signin', 'verify', 'secure', 'account', 'confirm'];

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }
  }
  return dp[m][n];
}

function getHostnameParts(url) {
  try {
    const parsed = new URL(url);
    return { hostname: parsed.hostname, pathname: parsed.pathname, search: parsed.search, full: parsed };
  } catch {
    // fallback for malformed URLs
    const match = url.match(/^https?:\/\/([^/?#]+)/i);
    const hostname = match ? match[1] : url;
    const pathStart = url.indexOf('/', url.indexOf('//') + 2);
    const pathname = pathStart > -1 ? url.slice(pathStart) : '/';
    const qIdx = url.indexOf('?');
    const search = qIdx > -1 ? url.slice(qIdx) : '';
    return { hostname, pathname, search, full: null };
  }
}

function analyzeURL(url) {
  const flags = [];
  const details = {};
  let score = 0;

  function addFlag(name, severity, message) {
    const pts = severity === 'high' ? 35 : severity === 'medium' ? 20 : 10;
    score = Math.min(100, score + pts);
    flags.push({ name, severity, message });
  }

  const { hostname, pathname, search } = getHostnameParts(url);
  const hostnameLower = hostname.toLowerCase();
  const pathAndQuery = (pathname + search).toLowerCase();
  const rawHostMatch = url.match(/^https?:\/\/([^/?#]+)/i);
  const rawHost = rawHostMatch ? rawHostMatch[1] : hostname;

  // 1. IP-based URL
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostnameLower)) {
    addFlag('ip_address', 'high', 'This link uses a raw IP address instead of a domain name, which is unusual for legitimate websites.');
    details.ipBased = true;
  }

  // 2. Excessive subdomains
  const subdomainParts = hostnameLower.split('.');
  if (subdomainParts.length > 4) {
    addFlag('excessive_subdomains', 'medium', `This link has an unusually deep chain of subdomains (${subdomainParts.length} levels), which is a common phishing tactic.`);
    details.subdomainLevels = subdomainParts.length;
  }

  // 3. Deceptive subdomain (brand in hostname but TLD+1 is not brand.<tld>)
  // Known brand-owned compounds (applepay.com etc.) are excluded via BRAND_OWNED_COMPOUNDS.
  // For multi-part TLDs (paypal.co.uk) we check subdomain labels to avoid both
  // false-positives (paypal.co.uk → legit) and misses (paypal.evil.co.uk → deceptive).
  const tld1 = getTLD1(hostnameLower);
  const hostParts = hostnameLower.split('.');
  const last2 = hostParts.slice(-2).join('.');
  const isMultiPartHost = MULTI_PART_TLDS.has(last2);

  if (!BRAND_OWNED_COMPOUNDS.has(tld1)) {
    for (const brand of BRANDS) {
      if (!hostnameLower.includes(brand)) continue;
      let deceptive;
      if (isMultiPartHost) {
        // For multi-part TLDs: deceptive only if brand appears in subdomain labels
        // (the labels before the 3-label registrable domain, e.g. 'paypal' in paypal.evil.co.uk)
        deceptive = hostParts.slice(0, -3).some((l) => l.includes(brand));
      } else {
        deceptive = !tld1.startsWith(brand + '.');
      }
      if (deceptive) {
        addFlag('deceptive_subdomain', 'high', `This link disguises itself as ${brand.charAt(0).toUpperCase() + brand.slice(1)} but leads to a different website.`);
        details.impersonatedBrand = brand;
        break;
      }
    }
  }

  // 4. Suspicious keywords in path/query
  // A single keyword (e.g. /login on github.com) is normal. Phishing URLs typically
  // chain multiple credential-harvest terms ("secure-login-verify-account"). Requiring
  // ≥2 distinct keywords cuts the dominant FP source without missing real attacks.
  const foundKeywords = SUSPICIOUS_KEYWORDS.filter(kw => pathAndQuery.includes(kw));
  if (foundKeywords.length >= 2) {
    addFlag('suspicious_keywords', 'medium', `The URL contains multiple suspicious terms (${foundKeywords.slice(0, 3).join(', ')}) that are often used in phishing pages.`);
    details.suspiciousKeywords = foundKeywords;
  }

  // 5. URL length
  if (url.length > 75) {
    addFlag('long_url', 'low', 'This URL is unusually long, which can be used to hide the true destination.');
    details.urlLength = url.length;
  }

  // 6. @ symbol
  if (url.includes('@')) {
    addFlag('at_symbol', 'high', 'This URL contains an @ symbol, which can trick your browser into ignoring everything before it and going to a different site.');
    details.hasAtSymbol = true;
  }

  // 7. Multiple hyphens in domain
  const hyphenCount = (hostnameLower.match(/-/g) || []).length;
  if (hyphenCount > 2) {
    addFlag('multiple_hyphens', 'medium', `The domain name contains ${hyphenCount} hyphens, which is uncommon for real websites.`);
    details.hyphenCount = hyphenCount;
  }

  // 8. Brand misspellings via Levenshtein
  const domainWithoutTld = hostnameLower.split('.').slice(0, -1).join('');
  for (const brand of BRANDS) {
    // skip exact matches (handled by deceptive subdomain check)
    if (domainWithoutTld === brand) continue;
    // check each domain label individually
    for (const label of hostnameLower.split('.').slice(0, -1)) {
      if (label === brand) continue;
      const dist = levenshtein(label, brand);
      if (dist > 0 && dist <= 2 && label.length >= brand.length - 2) {
        addFlag('brand_misspelling', 'high', `The domain "${label}" looks like a misspelling of "${brand}", a common trick used in phishing.`);
        details.misspelledBrand = { label, brand, distance: dist };
        break;
      }
    }
    if (details.misspelledBrand) break;
  }

  // 9. Brand name in URL path with credential-harvest keyword
  // Gated to avoid false positives on articles/docs that mention brands in paths.
  // Only fires if a different brand-impersonation check hasn't already flagged this URL.
  const alreadyFlaggedBrandImpersonation = flags.some(f =>
    f.name === 'deceptive_subdomain' || f.name === 'brand_misspelling'
  );
  // If the site itself is a major brand (e.g. amazon.com docs mentioning paypal),
  // path-based brand mentions are almost always legitimate.
  const hostIsKnownBrand = BRANDS.some(b => tld1.startsWith(b + '.'));
  if (!alreadyFlaggedBrandImpersonation && !hostIsKnownBrand) {
    const pathHasHarvestKeyword = HARVEST_ACTION_KEYWORDS.some(kw => pathAndQuery.includes(kw));
    if (pathHasHarvestKeyword) {
      for (const brand of BRANDS) {
        const brandInPath = new RegExp(`(^|[^a-z0-9])${brand}([^a-z0-9]|$)`).test(pathAndQuery);
        const hostnameOwnsBrand = hostnameLower.includes(brand);
        if (brandInPath && !hostnameOwnsBrand) {
          addFlag('brand_in_path', 'medium', `This link's address mentions "${brand}" in the path alongside sign-in terms, but the website itself isn't ${brand.charAt(0).toUpperCase() + brand.slice(1)}.`);
          details.brandInPath = brand;
          break;
        }
      }
    }
  }

  // 10. Homoglyph / non-ASCII in domain (check raw URL since URL parser converts to punycode)
  if (/[^\x00-\x7F]/.test(rawHost) || hostnameLower.startsWith('xn--')) {
    addFlag('homoglyph', 'high', 'The domain contains special Unicode characters that can make it look like a different, legitimate website.');
    details.hasNonAscii = true;
  }

  // 11. URL shortener
  if (SHORTENER_DOMAINS.some(d => hostnameLower === d || hostnameLower.endsWith('.' + d))) {
    addFlag('url_shortener', 'medium', 'This is a shortened URL that hides where the link actually goes.');
    details.isShortener = true;
  }

  // 12. Suspicious TLD
  const matchedTld = SUSPICIOUS_TLDS.find(tld => hostnameLower.endsWith(tld));
  if (matchedTld) {
    addFlag('suspicious_tld', 'low', `This website uses the "${matchedTld}" domain extension, which is frequently associated with spam and phishing.`);
    details.suspiciousTld = matchedTld;
  }

  // 13. Double extension pattern
  if (/\.\w{2,4}\.\w{2,4}$/.test(pathname) && /\.(exe|bat|cmd|scr|com|pif|vbs|js|msi|ps1)$/i.test(pathname)) {
    addFlag('double_extension', 'high', 'This link appears to disguise a dangerous file type by using a double file extension (e.g., document.pdf.exe).');
    details.doubleExtension = true;
  }

  // 14. Hex/percent encoding in domain (check raw URL, not parsed hostname)
  if (/%[0-9a-fA-F]{2}/.test(rawHost)) {
    addFlag('encoded_domain', 'medium', 'The domain name uses percent-encoded characters, which can be used to disguise the real destination.');
    details.encodedDomain = true;
  }

  // 15. Redirect chain indicators
  const searchLower = search.toLowerCase();
  const foundRedirects = REDIRECT_PARAMS.filter(p => searchLower.includes(p + '='));
  if (foundRedirects.length > 0) {
    addFlag('redirect_chain', 'medium', 'This URL contains redirect parameters that could send you to a different, potentially dangerous website.');
    details.redirectParams = foundRedirects;
  }

  return { score, flags, details };
}

export { analyzeURL };
