// Cloudflare Worker API client for threat intelligence lookups

const WORKER_URL = 'https://phishshield-api.workers.dev';

export async function fetchThreatAnalysis(url) {
  try {
    const resp = await fetch(`${WORKER_URL}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });

    if (!resp.ok) return null;

    const data = await resp.json();
    return {
      safeBrowsing: data.safeBrowsing || { isMalicious: false },
      phishTank: data.phishTank || { isPhishing: false },
      domainAge: data.domainAge || { isNew: false },
    };
  } catch (err) {
    console.warn('[PhishShield] API fetch failed:', err.message);
    return null;
  }
}
