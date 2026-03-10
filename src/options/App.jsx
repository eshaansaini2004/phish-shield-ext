import React, { useEffect, useState } from 'react';

const SETTINGS_KEY = 'phishshield_settings';

const DEFAULT_SETTINGS = {
  disableUrlAnalysis: false,
  disableML: false,
  disableDom: false,
  disableDownload: false,
  whitelist: [],
};

const LAYERS = [
  { key: 'disableUrlAnalysis', label: 'URL Heuristics', desc: '14 rule-based checks (IP URLs, brand spoofing, suspicious TLDs, etc.)' },
  { key: 'disableML',          label: 'ML Classifier',  desc: '18-feature neural network blended with heuristic score' },
  { key: 'disableDom',         label: 'DOM Analysis',   desc: 'Live page inspection for password fields on HTTP, cross-domain forms, scareware' },
  { key: 'disableDownload',    label: 'Download Interception', desc: 'Catches dangerous file types and MIME mismatches before they run' },
];

export default function App() {
  const [settings, setSettings] = useState(DEFAULT_SETTINGS);
  const [whitelistText, setWhitelistText] = useState('');
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    chrome.storage.sync.get(SETTINGS_KEY, (data) => {
      const stored = data[SETTINGS_KEY];
      if (!stored) return;
      const merged = { ...DEFAULT_SETTINGS, ...stored };
      setSettings(merged);
      setWhitelistText((merged.whitelist || []).join('\n'));
    });
  }, []);

  function toggleLayer(key) {
    setSettings((prev) => ({ ...prev, [key]: !prev[key] }));
    setSaved(false);
  }

  function handleWhitelistChange(e) {
    setWhitelistText(e.target.value);
    setSaved(false);
  }

  function save() {
    const whitelist = whitelistText
      .split('\n')
      .map((d) => d.trim().toLowerCase())
      .filter(Boolean);

    const toSave = { ...settings, whitelist };
    chrome.storage.sync.set({ [SETTINGS_KEY]: toSave }, () => {
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    });
  }

  return (
    <div style={styles.page}>
      <h1 style={styles.heading}>PhishShield Settings</h1>

      <section style={styles.section}>
        <h2 style={styles.sectionTitle}>Analysis Layers</h2>
        <p style={styles.sectionDesc}>Disable layers you don't want active. All are on by default.</p>
        {LAYERS.map(({ key, label, desc }) => (
          <label key={key} style={styles.toggleRow}>
            <div style={styles.toggleInfo}>
              <span style={styles.toggleLabel}>{label}</span>
              <span style={styles.toggleDesc}>{desc}</span>
            </div>
            <div
              style={{ ...styles.toggle, ...(settings[key] ? styles.toggleOff : styles.toggleOn) }}
              onClick={() => toggleLayer(key)}
              role="switch"
              aria-checked={!settings[key]}
              tabIndex={0}
              onKeyDown={(e) => e.key === ' ' && toggleLayer(key)}
            >
              <div style={{ ...styles.toggleThumb, ...(settings[key] ? styles.thumbOff : styles.thumbOn) }} />
            </div>
          </label>
        ))}
      </section>

      <section style={styles.section}>
        <h2 style={styles.sectionTitle}>Domain Whitelist</h2>
        <p style={styles.sectionDesc}>
          Domains listed here are always treated as safe. One per line (e.g. <code>google.com</code>).
        </p>
        <textarea
          style={styles.textarea}
          value={whitelistText}
          onChange={handleWhitelistChange}
          placeholder={'example.com\nmybank.com'}
          rows={6}
          spellCheck={false}
        />
      </section>

      <div style={styles.footer}>
        <button style={styles.saveBtn} onClick={save}>
          {saved ? 'Saved!' : 'Save Settings'}
        </button>
      </div>
    </div>
  );
}

const styles = {
  page: {
    maxWidth: 560,
    margin: '0 auto',
    padding: '32px 24px',
    fontFamily: "system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
    color: '#1a1a1a',
  },
  heading: {
    fontSize: 24,
    fontWeight: 700,
    marginBottom: 28,
    borderBottom: '2px solid #e0e0e0',
    paddingBottom: 12,
  },
  section: {
    marginBottom: 32,
  },
  sectionTitle: {
    fontSize: 16,
    fontWeight: 700,
    marginBottom: 4,
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
    color: '#555',
  },
  sectionDesc: {
    fontSize: 14,
    color: '#666',
    marginBottom: 16,
  },
  toggleRow: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '12px 0',
    borderBottom: '1px solid #f0f0f0',
    cursor: 'pointer',
  },
  toggleInfo: {
    display: 'flex',
    flexDirection: 'column',
    gap: 2,
    paddingRight: 16,
  },
  toggleLabel: {
    fontSize: 15,
    fontWeight: 600,
  },
  toggleDesc: {
    fontSize: 13,
    color: '#777',
  },
  toggle: {
    position: 'relative',
    width: 44,
    height: 24,
    borderRadius: 12,
    flexShrink: 0,
    transition: 'background 0.2s',
    cursor: 'pointer',
  },
  toggleOn: {
    background: '#4caf50',
  },
  toggleOff: {
    background: '#bdbdbd',
  },
  toggleThumb: {
    position: 'absolute',
    top: 2,
    width: 20,
    height: 20,
    borderRadius: '50%',
    background: '#fff',
    boxShadow: '0 1px 3px rgba(0,0,0,0.25)',
    transition: 'left 0.2s',
  },
  thumbOn: {
    left: 22,
  },
  thumbOff: {
    left: 2,
  },
  textarea: {
    width: '100%',
    padding: '10px 12px',
    fontSize: 14,
    fontFamily: 'monospace',
    border: '1px solid #d0d0d0',
    borderRadius: 6,
    resize: 'vertical',
    outline: 'none',
    boxSizing: 'border-box',
    color: '#1a1a1a',
    lineHeight: 1.6,
  },
  footer: {
    display: 'flex',
    justifyContent: 'flex-end',
  },
  saveBtn: {
    padding: '10px 28px',
    fontSize: 15,
    fontWeight: 600,
    background: '#1976d2',
    color: '#fff',
    border: 'none',
    borderRadius: 6,
    cursor: 'pointer',
  },
};
