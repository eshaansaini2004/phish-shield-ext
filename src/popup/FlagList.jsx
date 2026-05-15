import React from 'react';

const FLAG_LABELS = {
  ip_address: 'Raw IP Address',
  excessive_subdomains: 'Excessive Subdomains',
  deceptive_subdomain: 'Deceptive Subdomain',
  suspicious_keywords: 'Suspicious Keywords',
  long_url: 'Unusually Long URL',
  at_symbol: 'At Symbol in URL',
  multiple_hyphens: 'Multiple Hyphens',
  brand_misspelling: 'Brand Misspelling',
  brand_in_path: 'Brand Name in Path',
  homoglyph: 'Unicode Lookalike Domain',
  url_shortener: 'URL Shortener',
  suspicious_tld: 'Suspicious Domain Extension',
  double_extension: 'Double File Extension',
  encoded_domain: 'Encoded Domain',
  redirect_chain: 'Redirect Chain',
  ml_classifier: 'ML Classifier',
  safe_browsing_hit: 'Google Safe Browsing',
  phishtank_hit: 'PhishTank Database',
  new_domain: 'Newly Registered Domain',
  password_on_http: 'Password on Insecure Page',
  cross_domain_form: 'Cross-Domain Form',
  hidden_iframe: 'Hidden Iframe',
  scareware_text: 'Scareware Language',
  sensitive_field_http: 'Sensitive Field on HTTP',
  favicon_mismatch: 'Favicon Domain Mismatch',
  brand_impersonation: 'Brand Impersonation',
  meta_refresh: 'Auto-Redirect',
  right_click_disabled: 'Right-Click Disabled',
  beforeunload_handler: 'Exit Popup',
  'high-risk-extension': 'High-Risk File Type',
  'mime-mismatch': 'MIME Type Mismatch',
  'double-extension': 'Double File Extension',
  'phishing-filename': 'Known Phishing Filename',
  'http-source': 'Unencrypted Download',
  'suspicious-source': 'Suspicious Download Source',
};

function flagLabel(name) {
  if (FLAG_LABELS[name]) return FLAG_LABELS[name];
  // fallback: title-case the snake_case name
  return name.replace(/[-_]/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

export default function FlagList({ flags }) {
  if (!flags || flags.length === 0) {
    return (
      <div className="flag-list">
        <p className="flag-none">No suspicious activity detected.</p>
      </div>
    );
  }

  return (
    <div className="flag-list">
      <div className="flag-title">What we found:</div>
      {flags.map((flag, i) => (
        <div key={`${flag.name}-${i}`} className={`flag-item ${flag.severity}`}>
          <span className="flag-name">{flagLabel(flag.name)}</span>: {flag.message}
        </div>
      ))}
    </div>
  );
}
