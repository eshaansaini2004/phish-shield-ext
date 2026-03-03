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

export default function App() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const url = tabs[0]?.url;
      if (!url) {
        setLoading(false);
        return;
      }

      chrome.storage.local.get(url, (data) => {
        if (data[url]) {
          setResult(data[url]);
        }
        setLoading(false);
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

  return (
    <div>
      <RiskBadge score={result.score} level={level} />
      <ScoreBar score={result.score} />
      <FlagList flags={result.flags} />
      <HelpSection />
    </div>
  );
}
