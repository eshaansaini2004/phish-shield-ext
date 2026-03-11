import React, { useState, useEffect } from 'react';
import RiskBadge from './RiskBadge';
import ScoreBar from './ScoreBar';
import FlagList from './FlagList';
import HelpSection from './HelpSection';

function getLevel(score) {
  if (score <= 30) return 'safe';
  if (score <= 69) return 'suspicious';
  return 'dangerous';
}

const PHISHTANK_URL = 'https://www.phishtank.com/add_web_phishing.php';
const REPORTS_KEY = 'phishshield_reports';

export default function App() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(true);
  const [currentUrl, setCurrentUrl] = useState(null);
  const [reported, setReported] = useState(false);

  useEffect(() => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const url = tabs[0]?.url;
      if (!url) {
        setLoading(false);
        return;
      }
      setCurrentUrl(url);

      chrome.storage.local.get(url, (data) => {
        if (data[url]) {
          setResult(data[url]);
          setLoading(false);
          return;
        }

        // No cached result — trigger analysis now (popup opened on already-loaded page)
        chrome.runtime.sendMessage({ type: 'ANALYZE_URL', url, tabId: tabs[0].id });
        // keep loading=true; storage.onChanged listener below will pick up the result
      });

      // listen for updates in case analysis finishes while popup is open
      const listener = (changes) => {
        if (changes[url]?.newValue) {
          setResult(changes[url].newValue);
          setLoading(false);
        }
      };
      chrome.storage.onChanged.addListener(listener);
      return () => chrome.storage.onChanged.removeListener(listener);
    });
  }, []);

  if (loading || !result) {
    return (
      <div>
        <RiskBadge score={0} level="loading" />
        <div className="spinner">
          <div className="spinner-circle" />
          <span className="spinner-text">Analyzing page...</span>
        </div>
      </div>
    );
  }

  const level = getLevel(result.score);

  function handleReport() {
    chrome.storage.local.get(REPORTS_KEY, (data) => {
      const existing = data[REPORTS_KEY] || [];
      existing.push({ url: currentUrl, reportedAt: Date.now(), score: result.score });
      chrome.storage.local.set({ [REPORTS_KEY]: existing });
    });
    chrome.tabs.create({ url: PHISHTANK_URL });
    setReported(true);
    setTimeout(() => setReported(false), 2000);
  }

  return (
    <div>
      <RiskBadge score={result.score} level={level} />
      <ScoreBar score={result.score} />
      <FlagList flags={result.flags} />
      <HelpSection />
      <div className="report-row">
        {reported
          ? <span className="report-feedback">Reported!</span>
          : <button className="report-btn" onClick={handleReport}>⚑ Report as Phishing</button>
        }
      </div>
    </div>
  );
}
