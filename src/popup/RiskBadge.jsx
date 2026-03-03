import React from 'react';

const ShieldCheck = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    <path d="M9 12l2 2 4-4"/>
  </svg>
);

const WarningTriangle = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
    <line x1="12" y1="9" x2="12" y2="13"/>
    <line x1="12" y1="17" x2="12.01" y2="17"/>
  </svg>
);

const XCircle = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10"/>
    <line x1="15" y1="9" x2="9" y2="15"/>
    <line x1="9" y1="9" x2="15" y2="15"/>
  </svg>
);

const icons = {
  safe: ShieldCheck,
  suspicious: WarningTriangle,
  dangerous: XCircle,
  loading: null,
};

const labels = {
  safe: 'SAFE',
  suspicious: 'SUSPICIOUS',
  dangerous: 'DANGEROUS',
  loading: 'ANALYZING...',
};

export default function RiskBadge({ score, level }) {
  const Icon = icons[level];
  return (
    <div className={`risk-badge ${level}`}>
      {Icon && <Icon />}
      <span className="label">{labels[level]}</span>
      {level !== 'loading' && (
        <span style={{ fontSize: '15px', marginTop: 4 }}>Score: {score}/100</span>
      )}
    </div>
  );
}
