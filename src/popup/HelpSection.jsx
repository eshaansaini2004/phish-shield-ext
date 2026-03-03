import React, { useState } from 'react';

export default function HelpSection() {
  const [open, setOpen] = useState(false);

  return (
    <div className="help-section">
      <button className="help-toggle" onClick={() => setOpen(!open)}>
        What does this mean? {open ? '\u25B2' : '\u25BC'}
      </button>
      {open && (
        <div className="help-content">
          <p>
            Phishing is when attackers create fake websites that look like real ones
            to steal your passwords, credit card numbers, or personal information.
            These sites often arrive through email links or ads.
          </p>
          <p>
            PhishShield analyzes the current page by checking the URL structure,
            page content, and known threat databases. It assigns a risk score from
            0 (completely safe) to 100 (almost certainly malicious).
          </p>
          <p>
            If you see a yellow or red warning, avoid entering any personal
            information on the page. Close the tab and navigate to the real website
            by typing the address directly into your browser.
          </p>
        </div>
      )}
    </div>
  );
}
