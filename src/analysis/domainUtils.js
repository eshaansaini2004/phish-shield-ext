// Shared domain helpers used by both URL and DOM analysis layers.

// Known two-part TLD suffixes — getTLD1 must take three labels for these.
const MULTI_PART_TLDS = new Set([
  'co.uk', 'co.in', 'co.jp', 'co.au', 'co.nz', 'co.za',
  'com.au', 'com.br', 'com.cn', 'com.mx', 'com.ar',
  'org.uk', 'net.au', 'gov.uk', 'ac.uk', 'edu.au',
]);

// Returns registrable domain (eTLD+1), handling two-part TLDs like co.uk.
function getTLD1(hostname) {
  if (!hostname) return hostname;
  const parts = hostname.toLowerCase().split('.');
  if (parts.length >= 3 && MULTI_PART_TLDS.has(parts.slice(-2).join('.'))) {
    return parts.slice(-3).join('.');
  }
  if (parts.length >= 2) return parts.slice(-2).join('.');
  return hostname.toLowerCase();
}

// True when two hostnames share the same registrable domain.
// www.foo.com and api.foo.com are NOT cross-domain; foo.com and bar.com are.
function sameRegistrableDomain(a, b) {
  if (!a || !b) return false;
  return getTLD1(a) === getTLD1(b);
}

export { MULTI_PART_TLDS, getTLD1, sameRegistrableDomain };
