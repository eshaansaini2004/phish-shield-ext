import React from 'react';

function barColor(score) {
  if (score <= 30) return '#4caf50';
  if (score <= 50) return '#ffa000';
  if (score <= 69) return '#f57c00';
  return '#f44336';
}

export default function ScoreBar({ score }) {
  return (
    <div className="score-bar">
      <div className="score-label">Risk Score: {score}/100</div>
      <div className="bar-track">
        <div
          className="bar-fill"
          style={{
            width: `${Math.min(100, Math.max(0, score))}%`,
            background: barColor(score),
          }}
        />
      </div>
    </div>
  );
}
