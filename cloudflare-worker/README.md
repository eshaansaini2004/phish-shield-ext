# PhishShield API - Cloudflare Worker

Backend proxy that checks URLs against Google Safe Browsing, PhishTank, and domain age databases.

## API

**POST /analyze**

Request:
```json
{ "url": "https://example.com" }
```

Response:
```json
{
  "safeBrowsing": { "isMalicious": false, "threatType": null },
  "phishTank": { "isPhishing": false, "verified": false },
  "domainAge": { "ageDays": 9500, "isNew": false },
  "error": null
}
```

If an individual API fails, that section includes an `error` field but the rest still returns.

## Setup

### 1. Get API Keys

**Google Safe Browsing:**
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a project (or use existing)
3. Enable "Safe Browsing API" under APIs & Services > Library
4. Create an API key under APIs & Services > Credentials

**PhishTank (optional):**
1. Register at [phishtank.com](https://www.phishtank.com/)
2. Get your API key at [phishtank.com/api_info.php](https://www.phishtank.com/api_info.php)

Domain age lookup uses domainsdb.info which is free and requires no key.

### 2. Deploy

```bash
npm install -g wrangler
wrangler login
cd cloudflare-worker
wrangler deploy
```

### 3. Set Secrets

```bash
wrangler secret put GOOGLE_SAFE_BROWSING_KEY
wrangler secret put PHISHTANK_API_KEY
```

The worker will be available at `https://phishshield-api.<your-subdomain>.workers.dev/analyze`.
