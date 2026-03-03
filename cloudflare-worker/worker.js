export default {
  async fetch(request, env) {
    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    if (request.method !== 'POST') {
      return jsonResponse({ error: 'Method not allowed' }, 405);
    }

    const url = new URL(request.url);
    if (url.pathname !== '/analyze') {
      return jsonResponse({ error: 'Not found' }, 404);
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return jsonResponse({ error: 'Invalid JSON body' }, 400);
    }

    if (!body.url || typeof body.url !== 'string') {
      return jsonResponse({ error: 'Missing or invalid "url" field' }, 400);
    }

    const targetUrl = body.url;
    let domain;
    try {
      domain = new URL(targetUrl).hostname;
    } catch {
      return jsonResponse({ error: 'Invalid URL' }, 400);
    }

    // Run all checks in parallel, each one catches its own errors
    const [safeBrowsing, phishTank, domainAge] = await Promise.all([
      checkSafeBrowsing(targetUrl, env.GOOGLE_SAFE_BROWSING_KEY),
      checkPhishTank(targetUrl, env.PHISHTANK_API_KEY),
      checkDomainAge(domain),
    ]);

    return jsonResponse({
      safeBrowsing,
      phishTank,
      domainAge,
      error: null,
    });
  },
};

// --- Google Safe Browsing ---

async function checkSafeBrowsing(url, apiKey) {
  const fallback = { isMalicious: false, threatType: null, error: 'API key not configured' };
  if (!apiKey) return fallback;

  try {
    const resp = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: { clientId: 'phishshield', clientVersion: '1.0.0' },
          threatInfo: {
            threatTypes: [
              'MALWARE',
              'SOCIAL_ENGINEERING',
              'UNWANTED_SOFTWARE',
              'POTENTIALLY_HARMFUL_APPLICATION',
            ],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url }],
          },
        }),
      }
    );

    if (!resp.ok) {
      return { isMalicious: false, threatType: null, error: `HTTP ${resp.status}` };
    }

    const data = await resp.json();
    if (data.matches && data.matches.length > 0) {
      return {
        isMalicious: true,
        threatType: data.matches[0].threatType,
      };
    }
    return { isMalicious: false, threatType: null };
  } catch (err) {
    return { isMalicious: false, threatType: null, error: err.message };
  }
}

// --- PhishTank ---

async function checkPhishTank(url, apiKey) {
  try {
    const params = new URLSearchParams({
      url,
      format: 'json',
    });
    if (apiKey) {
      params.set('app_key', apiKey);
    }

    const resp = await fetch('https://checkurl.phishtank.com/checkurl/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });

    if (!resp.ok) {
      return { isPhishing: false, verified: false, error: `HTTP ${resp.status}` };
    }

    const data = await resp.json();
    const results = data.results || {};
    return {
      isPhishing: results.in_database === true,
      verified: results.verified === true,
    };
  } catch (err) {
    return { isPhishing: false, verified: false, error: err.message };
  }
}

// --- Domain Age (domainsdb.info - free, no key) ---

async function checkDomainAge(hostname) {
  try {
    // Strip subdomains: take last two parts (or last part for TLDs like .co.uk this is good enough)
    const parts = hostname.split('.');
    const domain = parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
    const [name, zone] = domain.split('.');

    const resp = await fetch(
      `https://api.domainsdb.info/v1/domains/search?domain=${encodeURIComponent(name)}&zone=${encodeURIComponent(zone)}`,
      { signal: AbortSignal.timeout(5000) }
    );

    if (!resp.ok) {
      return { ageDays: null, isNew: false, error: `HTTP ${resp.status}` };
    }

    const data = await resp.json();
    const match = (data.domains || []).find(
      (d) => d.domain === domain
    );

    if (!match || !match.create_date) {
      return { ageDays: null, isNew: false };
    }

    const created = new Date(match.create_date);
    const ageDays = Math.floor((Date.now() - created.getTime()) / (1000 * 60 * 60 * 24));
    return {
      ageDays,
      isNew: ageDays < 30,
    };
  } catch (err) {
    return { ageDays: null, isNew: false, error: err.message };
  }
}

// --- Helpers ---

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
    },
  });
}
