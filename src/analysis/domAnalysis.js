// Layer 2: DOM / Page Content Analysis
// Scans the live page for phishing indicators in the DOM

const KNOWN_BRANDS = [
  'paypal', 'google', 'amazon', 'facebook', 'apple', 'microsoft',
  'netflix', 'instagram', 'twitter', 'chase', 'bankofamerica',
  'wellsfargo', 'citibank', 'ebay'
];

const SENSITIVE_FIELD_PATTERNS = [
  'ssn', 'social.security', 'social-security', 'credit.card', 'credit-card',
  'card.number', 'card-number', 'cvv', 'routing', 'bank.account', 'bank-account'
];

const SCAREWARE_PHRASES = [
  'your computer has a virus',
  'call microsoft',
  'your account has been suspended',
  'your account has been compromised',
  'urgent'
];

const PHONE_REGEX = /\d{3}[-.\s]\d{3}[-.\s]\d{4}/;

const SEVERITY_POINTS = { low: 10, medium: 20, high: 35 };

function getHostname(url) {
  try {
    return new URL(url, location.href).hostname;
  } catch {
    return null;
  }
}

function isExternal(hostname) {
  return hostname && hostname !== location.hostname;
}

// Check 1: Password field on non-HTTPS
function checkPasswordOnHttp() {
  if (location.protocol === 'https:') return null;
  const pwFields = document.querySelectorAll('input[type="password"]');
  if (pwFields.length === 0) return null;
  return {
    name: 'password_on_http',
    severity: 'high',
    message: 'This page asks for a password but is not using a secure connection. Your password could be stolen.'
  };
}

// Check 2: Form submits to different domain
function checkCrossDomainForms() {
  const flags = [];
  document.querySelectorAll('form[action]').forEach(form => {
    const actionHost = getHostname(form.action);
    if (isExternal(actionHost)) {
      flags.push({
        name: 'cross_domain_form',
        severity: 'high',
        message: `A form on this page sends your data to a different website (${actionHost}). This is a common phishing trick.`
      });
    }
  });
  return flags;
}

// Check 3: Hidden iframes loading external URLs
function checkHiddenIframes() {
  const flags = [];
  document.querySelectorAll('iframe[src]').forEach(iframe => {
    const style = window.getComputedStyle(iframe);
    const isHidden =
      style.display === 'none' ||
      style.visibility === 'hidden' ||
      parseInt(style.width) <= 1 ||
      parseInt(style.height) <= 1 ||
      iframe.offsetWidth === 0 ||
      iframe.offsetHeight === 0;

    if (!isHidden) return;
    const srcHost = getHostname(iframe.src);
    if (isExternal(srcHost)) {
      flags.push({
        name: 'hidden_iframe',
        severity: 'high',
        message: `This page has a hidden frame loading content from ${srcHost}. Legitimate sites rarely do this.`
      });
    }
  });
  return flags;
}

// Check 4: Fake system alert / scareware text
function checkScarewareText() {
  const bodyText = document.body ? document.body.innerText.toLowerCase() : '';
  const hasScarePhrase = SCAREWARE_PHRASES.some(phrase => bodyText.includes(phrase));
  const hasPhone = PHONE_REGEX.test(document.body ? document.body.innerText : '');

  if (hasScarePhrase && hasPhone) {
    return {
      name: 'scareware_text',
      severity: 'medium',
      message: 'This page contains alarming language and a phone number. This is a common tech support scam tactic.'
    };
  }
  return null;
}

// Check 5: Sensitive fields on HTTP
function checkSensitiveFieldsOnHttp() {
  if (location.protocol === 'https:') return null;
  const flags = [];
  document.querySelectorAll('input').forEach(input => {
    const identifiers = [
      (input.name || '').toLowerCase(),
      (input.id || '').toLowerCase(),
      (input.placeholder || '').toLowerCase()
    ].join(' ');

    const match = SENSITIVE_FIELD_PATTERNS.find(p => identifiers.includes(p));
    if (match) {
      flags.push({
        name: 'sensitive_field_http',
        severity: 'high',
        message: `This page asks for sensitive information (${match}) without a secure connection.`
      });
    }
  });
  return flags;
}

// Check 6: Favicon domain mismatch
function checkFaviconMismatch() {
  const iconLink = document.querySelector('link[rel~="icon"]');
  if (!iconLink || !iconLink.href) return null;
  const iconHost = getHostname(iconLink.href);
  if (isExternal(iconHost)) {
    return {
      name: 'favicon_mismatch',
      severity: 'medium',
      message: `The site icon is loaded from a different domain (${iconHost}), which may indicate impersonation.`
    };
  }
  return null;
}

// Check 7: Brand name in title/h1 but not in domain
function checkBrandImpersonation() {
  const flags = [];
  const title = (document.title || '').toLowerCase();
  const h1Elements = document.querySelectorAll('h1');
  const h1Text = Array.from(h1Elements).map(el => el.textContent.toLowerCase()).join(' ');
  const pageText = title + ' ' + h1Text;
  const domain = location.hostname.toLowerCase();

  KNOWN_BRANDS.forEach(brand => {
    if (pageText.includes(brand) && !domain.includes(brand)) {
      flags.push({
        name: 'brand_impersonation',
        severity: 'high',
        message: `This page mentions "${brand}" but the website address doesn't belong to ${brand}. It may be impersonating that brand.`
      });
    }
  });
  return flags;
}

// Check 8: Meta refresh redirect with short delay
function checkMetaRefresh() {
  const meta = document.querySelector('meta[http-equiv="refresh"]');
  if (!meta) return null;
  const content = meta.getAttribute('content') || '';
  const delayMatch = content.match(/^\s*(\d+)/);
  if (delayMatch && parseInt(delayMatch[1]) < 5) {
    return {
      name: 'meta_refresh',
      severity: 'medium',
      message: 'This page will quickly redirect you elsewhere. Phishing sites use this to move you before you notice.'
    };
  }
  return null;
}

// Check 9: Right-click disabled
function checkRightClickDisabled() {
  const onCtx = document.oncontextmenu || (document.body && document.body.oncontextmenu);
  const attrDoc = document.documentElement.getAttribute('oncontextmenu');
  const attrBody = document.body ? document.body.getAttribute('oncontextmenu') : null;

  if (onCtx || (attrDoc && attrDoc.includes('false')) || (attrBody && attrBody.includes('false'))) {
    return {
      name: 'right_click_disabled',
      severity: 'low',
      message: 'This page prevents right-clicking. Some phishing sites do this to stop you from inspecting the page.'
    };
  }
  return null;
}

// Check 10: Excessive popups indicator (onbeforeunload)
function checkBeforeUnload() {
  const attr = window.onbeforeunload ||
    document.documentElement.getAttribute('onbeforeunload') ||
    (document.body && document.body.getAttribute('onbeforeunload'));

  if (attr) {
    return {
      name: 'beforeunload_handler',
      severity: 'low',
      message: 'This page tries to prevent you from leaving. Scareware sites commonly do this.'
    };
  }
  return null;
}

/**
 * Run all DOM-based phishing checks against the current page.
 * Reads directly from document/window globals.
 * @returns {{ score: number, flags: Array<{name: string, severity: string, message: string}>, details: object }}
 */
function analyzePage() {
  const flags = [];
  const details = {};

  const checks = [
    checkPasswordOnHttp,
    checkCrossDomainForms,
    checkHiddenIframes,
    checkScarewareText,
    checkSensitiveFieldsOnHttp,
    checkFaviconMismatch,
    checkBrandImpersonation,
    checkMetaRefresh,
    checkRightClickDisabled,
    checkBeforeUnload,
  ];

  checks.forEach(check => {
    try {
      const result = check();
      if (!result) return;
      if (Array.isArray(result)) {
        flags.push(...result);
      } else {
        flags.push(result);
      }
    } catch (err) {
      // Don't let one check crash everything
      details[check.name + '_error'] = err.message;
    }
  });

  let score = flags.reduce((sum, f) => sum + (SEVERITY_POINTS[f.severity] || 0), 0);
  score = Math.min(score, 100);

  details.checksRun = checks.length;
  details.flagsFound = flags.length;
  details.url = location.href;
  details.protocol = location.protocol;

  return { score, flags, details };
}

export { analyzePage };
