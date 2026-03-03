// Layer 3: Download interception and analysis

const HIGH_RISK_EXTENSIONS = new Set([
  '.exe', '.bat', '.cmd', '.scr', '.vbs', '.pif', '.com',
  '.msi', '.ps1', '.jar', '.hta', '.wsf', '.reg', '.inf', '.dll'
]);

const MIME_EXTENSION_MAP = {
  'application/pdf': ['.pdf'],
  'image/jpeg': ['.jpg', '.jpeg'],
  'image/png': ['.png'],
  'text/plain': ['.txt'],
  'application/zip': ['.zip'],
};

const DOUBLE_EXT_REGEX = /\.(pdf|doc|docx|jpg|png|txt|zip)\.(exe|bat|cmd|scr|vbs|ps1)$/i;

const PHISHING_FILENAMES = new Set([
  'invoice.exe', 'document.exe', 'update.exe', 'setup.exe',
  'report.pdf.exe', 'file.exe', 'attachment.exe', 'scan.exe',
  'receipt.exe', 'payment.exe'
]);

const SUSPICIOUS_URL_KEYWORDS = ['login', 'secure', 'account', 'update', 'verify'];

const SEVERITY_SCORES = { low: 10, medium: 20, high: 35 };

function getExtension(filename) {
  if (!filename) return '';
  const basename = filename.split(/[/\\]/).pop();
  const dot = basename.lastIndexOf('.');
  return dot === -1 ? '' : basename.slice(dot).toLowerCase();
}

function getBasename(filename) {
  if (!filename) return '';
  return filename.split(/[/\\]/).pop().toLowerCase();
}

function urlContainsSuspiciousKeyword(url) {
  if (!url) return false;
  const lower = url.toLowerCase();
  return SUSPICIOUS_URL_KEYWORDS.find(kw => lower.includes(kw)) || null;
}

function analyzeDownload(downloadItem) {
  const flags = [];
  let score = 0;

  const filename = downloadItem.filename || '';
  const ext = getExtension(filename);
  const basename = getBasename(filename);
  const mime = (downloadItem.mime || '').toLowerCase();
  const url = downloadItem.url || '';
  const referrer = downloadItem.referrer || '';

  // 1. High-risk extension
  if (HIGH_RISK_EXTENSIONS.has(ext)) {
    flags.push({
      name: 'high-risk-extension',
      severity: 'high',
      message: `This file type (${ext}) can run programs on your computer and is commonly used in attacks.`,
    });
  }

  // 2. MIME type mismatch
  if (mime && MIME_EXTENSION_MAP[mime]) {
    const expected = MIME_EXTENSION_MAP[mime];
    if (ext && !expected.includes(ext)) {
      flags.push({
        name: 'mime-mismatch',
        severity: 'high',
        message: `The file claims to be ${mime} but has a ${ext} extension. This is a common disguise technique.`,
      });
    }
  }

  // 3. Double extension
  if (DOUBLE_EXT_REGEX.test(basename)) {
    flags.push({
      name: 'double-extension',
      severity: 'high',
      message: 'This file uses a double extension to disguise its real type. It may look like a document but is actually executable.',
    });
  }

  // 4. Generic phishing filenames
  if (PHISHING_FILENAMES.has(basename)) {
    flags.push({
      name: 'phishing-filename',
      severity: 'medium',
      message: `The filename "${basename}" is commonly used in phishing attacks to trick users into opening malicious files.`,
    });
  }

  // 5. Auto-download (not user-initiated)
  if (!downloadItem.byExtensionId) {
    flags.push({
      name: 'auto-download',
      severity: 'medium',
      message: 'This download was not initiated by a user action. Automatic downloads can be a sign of a malicious page.',
    });
  }

  // 6. HTTP source
  if (url.startsWith('http://')) {
    flags.push({
      name: 'http-source',
      severity: 'low',
      message: 'This file is being downloaded over an unencrypted connection. The file could have been tampered with in transit.',
    });
  }

  // 7. Suspicious source URL
  const suspiciousKw = urlContainsSuspiciousKeyword(url) || urlContainsSuspiciousKeyword(referrer);
  if (suspiciousKw) {
    flags.push({
      name: 'suspicious-source',
      severity: 'medium',
      message: `The download source contains the suspicious keyword "${suspiciousKw}", which is often used in phishing pages.`,
    });
  }

  // Calculate score
  for (const flag of flags) {
    score += SEVERITY_SCORES[flag.severity] || 0;
  }
  if (score > 100) score = 100;

  return {
    score,
    flags,
    details: {
      filename: basename,
      extension: ext,
      mime,
      url,
      referrer,
    },
    shouldBlock: score >= 60,
  };
}

function setupDownloadListener(onResult) {
  if (!chrome?.downloads?.onDeterminingFilename) return;

  chrome.downloads.onDeterminingFilename.addListener((downloadItem, suggest) => {
    const result = analyzeDownload(downloadItem);
    onResult(downloadItem.id, result);
    suggest(); // don't alter the filename
  });
}

export { analyzeDownload, setupDownloadListener };
