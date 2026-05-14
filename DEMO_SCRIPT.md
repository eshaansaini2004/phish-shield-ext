# PhishShield Demo Script (2 minutes)

## URLs to Use

Copy these somewhere you can paste quickly during the recording:

| Result | URL |
|--------|-----|
| Green  | `https://en.wikipedia.org/wiki/Cybersecurity` |
| Yellow | `http://portal-login.club/account` |
| Red    | `http://192.0.2.1/paypal/login/verify` |

> **Test all three before recording.** The yellow URL is designed to always land 31–68 regardless of ML confidence,
> but confirm it shows a yellow badge on your machine first. Green and red are very reliable.

---

## Before You Start

- Extension is installed and the shield icon is pinned to the Chrome toolbar
- Zoom Chrome to 125% so the popup is readable on screen (`Cmd +` twice)
- Have the URLs above ready to paste — typing live wastes time and risks typos

---

## Step 1 — Green (0:00 – 0:35)

**Navigate to:**
```
https://en.wikipedia.org/wiki/Cybersecurity

```

Wait for the page to fully load, then click the PhishShield shield icon in the toolbar.

**Say:**
> "PhishShield scans every page automatically the moment you navigate to it. On a legitimate site like Wikipedia — clean score, no flags."

**Expected result:** Green badge, score 3–15, "No suspicious activity detected."

---

## Step 2 — Yellow (0:35 – 1:10)

**Navigate to (include the `http://`):**
```
http://portal-login.club/account

```

The page will fail to load — that is fine and expected.

Click the PhishShield icon.

**Say:**
> "The page never loaded, but PhishShield already flagged it from the URL alone — no page content needed.
> It caught two things: the `.club` domain extension is associated with spam, and the path contains the word 'account',
> a common pattern in credential-harvesting pages."

**Expected result:** Yellow badge, score 35–55, flags for `suspicious_tld` and `suspicious_keywords`.

Point at a flag and read the plain-English description aloud — this is the accessibility feature.

---

## Step 3 — Red (1:10 – 1:45)

**Navigate to (include the `http://`):**
```
http://192.0.2.1/paypal/login/verify

```

The page will fail to load — expected.

Click the PhishShield icon.

**Say:**
> "Classic phishing structure. A raw IP address instead of a real domain name, with PayPal's name buried
> in the path to look convincing. Three flags fire instantly — score in the 80s."

**Expected result:** Red badge, score 75–90, flags for `ip_address`, `brand_in_path`, and `suspicious_keywords`.

Read the `ip_address` flag description aloud:
> "This link uses a raw IP address instead of a domain name, which is unusual for legitimate websites."

---

## Step 4 — Wrap Up (1:45 – 2:00)

Right-click the shield icon and select **Options** to open the settings page.

**Say:**
> "Users can toggle individual analysis layers on or off, or whitelist domains they trust.
> All four layers run entirely in the browser — nothing is sent to a server unless you opt in
> to the threat intelligence lookup."

Done.

---

## If Someone Asks About False Positives

> "On ad-heavy or login-heavy real-world sites, the page-content layer can over-flag — ads look
> like hidden iframes, and every login form is technically suspicious. That's a known limitation.
> The layer toggles and domain whitelist in Settings are how you handle it today, and user testing
> to tune the thresholds is the next step."

---


