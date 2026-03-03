import React from 'react';

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
        <div key={i} className={`flag-item ${flag.severity}`}>
          <span className="flag-name">{flag.name}</span>: {flag.message}
        </div>
      ))}
    </div>
  );
}
