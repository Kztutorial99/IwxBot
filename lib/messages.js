// VulnScan Bot — Message Templates v2
// Design: clean ASCII, no emoji, monospace blocks

function escMd(str) {
  if (typeof str !== 'string') str = String(str);
  return str.replace(/_/g, '\\_').replace(/\*/g, '\\*');
}

// ── Layout primitives ────────────────────────────────────────────────────────

const W = 38;
const THIN  = '\u2500'; // ─
const THICK = '\u2501'; // ━
const VLINE = '\u2502'; // │

function rule(char, width) { return '`' + char.repeat(width || W) + '`'; }
function box(text, width) {
  const w = width || W;
  const padded = text.length > w - 2 ? text.substring(0, w - 2) : text;
  return '`' + ' ' + padded.padEnd(w - 1) + '`';
}
function boxCenter(text, width) {
  const w = width || W;
  const total = w - 2;
  const pad = Math.max(0, Math.floor((total - text.length) / 2));
  const line = ' '.repeat(pad) + text + ' '.repeat(total - pad - text.length);
  return '`' + line.substring(0, w - 1).padEnd(w - 1) + '`';
}
function kv(label, value, width) {
  const w = width || W;
  const lbl = String(label).substring(0, 16).padEnd(16);
  const val = String(value).substring(0, w - 18);
  return '`' + ' ' + lbl + ' ' + val.padEnd(w - 18) + '`';
}

function header(title) {
  return [
    rule(THICK),
    boxCenter(title.toUpperCase()),
    rule(THICK),
  ].join('\n');
}

function subheader(title) {
  return [
    rule(THIN),
    box('  ' + title),
    rule(THIN),
  ].join('\n');
}

// ── Status / badge helpers ───────────────────────────────────────────────────

function statusStr(val) {
  if (val === true  || val === 'A')     return 'PASS';
  if (val === false || val === 'F')     return 'FAIL';
  if (val === 'B')                      return 'WARN';
  return 'INFO';
}

function riskStr(level) {
  return { CRITICAL:'CRITICAL', HIGH:'HIGH   ', MEDIUM:'MEDIUM ', LOW:'LOW    ' }[level] || 'UNKNOWN';
}

// ── Progress bar (animated scan) ─────────────────────────────────────────────
// Returns a message string for a given step index 0..steps-1

const STEPS = [
  { pct:  5, label: 'Initializing scan...' },
  { pct: 20, label: 'Checking SSL/TLS certificate...' },
  { pct: 38, label: 'Auditing HTTP security headers...' },
  { pct: 55, label: 'Testing SQL injection...' },
  { pct: 70, label: 'Testing XSS vulnerabilities...' },
  { pct: 82, label: 'Auditing CORS configuration...' },
  { pct: 92, label: 'Testing open redirects...' },
  { pct:100, label: 'Compiling report...' },
];

function progressBar(pct) {
  const filled = Math.round(pct / 100 * 20);
  const bar = '>'.repeat(filled) + '-'.repeat(20 - filled);
  return '[' + bar + '] ' + String(pct).padStart(3) + '%';
}

function scanProgressMessage(url, stepIndex) {
  const step = STEPS[Math.min(stepIndex, STEPS.length - 1)];
  const displayUrl = url.length > 34 ? url.substring(0, 34) + '...' : url;
  return [
    header('Scanning Target'),
    '',
    box(' Target : ' + displayUrl),
    '',
    rule(THIN),
    '`' + ' ' + progressBar(step.pct).padEnd(W - 1) + '`',
    rule(THIN),
    '',
    box(' ' + step.label),
    '',
    '_Do not close. Results appear when done._',
  ].join('\n');
}

function scanningMessage(url) { return scanProgressMessage(url, 0); }

// ── Welcome ──────────────────────────────────────────────────────────────────

function welcomeMessage(firstName) {
  const name = escMd(firstName || 'Operator');
  return [
    header('IwxBot v1.0'),
    '',
    box(' Welcome, ' + name + '.'),
    '',
    rule(THIN),
    boxCenter('WEB VULNERABILITY SCANNER'),
    rule(THIN),
    '',
    box(' Modules available:'),
    box('  SQL Injection Detection'),
    box('  XSS Vulnerability Testing'),
    box('  HTTP Security Headers'),
    box('  SSL/TLS Certificate Check'),
    box('  CORS Misconfiguration'),
    box('  Open Redirect Detection'),
    '',
    rule(THICK),
    '_Use the menu below to get started._',
  ].join('\n');
}

// ── Main menu ────────────────────────────────────────────────────────────────

function mainMenuMessage() {
  return [
    header('Main Menu'),
    '',
    box(' SCAN      Run a vulnerability scan'),
    box(' QUICK     Fast headers + SSL only'),
    box(' FULL      All 6 modules combined'),
    box(' MODULES   About scanner modules'),
    box(' REPORTS   View last scan result'),
    box(' HELP      Usage and commands'),
    '',
    rule(THIN),
    '_Select a module from the buttons below._',
  ].join('\n');
}

// ── Help ─────────────────────────────────────────────────────────────────────

function helpMessage() {
  return [
    header('Help'),
    '',
    subheader('Commands'),
    box('  /start       Open main menu'),
    box('  /scan <url>  Full scan (inline)'),
    box('  /help        This message'),
    box('  /cancel      Abort current scan'),
    '',
    subheader('Supported URL formats'),
    box('  https://example.com'),
    box('  http://example.com'),
    box('  example.com  (auto HTTPS)'),
    '',
    subheader('Scan types'),
    kv('Full Scan', 'All 6 modules'),
    kv('Quick Scan', 'Headers + SSL'),
    kv('Headers', 'Security headers'),
    kv('SSL Check', 'TLS certificate'),
    kv('SQLi Test', 'Injection vectors'),
    kv('XSS Test', 'Script injection'),
    kv('CORS Audit', 'Cross-origin'),
    kv('Redirect', 'Open redirect'),
    '',
    rule(THIN),
    '_Only scan targets you own or have_',
    '_explicit written permission to test._',
  ].join('\n');
}

// ── About ────────────────────────────────────────────────────────────────────

function aboutMessage() {
  return [
    header('About IwxBot'),
    '',
    kv('Version', 'v1.0.0'),
    kv('Type', 'Recon + Audit'),
    kv('Mode', 'Webhook (Vercel)'),
    kv('Author', 'Kztutorial99'),
    '',
    rule(THIN),
    box(' Modules:'),
    kv('  SQLi', 'Error-based detection'),
    kv('  XSS', 'Reflected payload check'),
    kv('  Headers', '10 security headers'),
    kv('  SSL', 'TLS + HSTS + redirect'),
    kv('  CORS', 'Origin spoofing test'),
    kv('  Redirect', 'Open redirect vectors'),
    '',
    rule(THIN),
    '_Unauthorized scanning is illegal._',
  ].join('\n');
}

// ── Scan prompt ──────────────────────────────────────────────────────────────

function scanPromptMessage(scanType) {
  const labels = {
    full:     'Full Scan (All Modules)',
    quick:    'Quick Scan (Headers + SSL)',
    headers:  'Headers Analysis',
    ssl:      'SSL/TLS Check',
    sqli:     'SQL Injection Test',
    xss:      'XSS Vulnerability Test',
    cors:     'CORS Audit',
    redirect: 'Open Redirect Test',
  };
  return [
    header('Enter Target'),
    '',
    kv('Module', labels[scanType] || scanType),
    '',
    rule(THIN),
    '',
    box(' Send the target URL:'),
    box('  https://example.com'),
    box('  example.com'),
    '',
    rule(THIN),
    '_Type /cancel to abort._',
  ].join('\n');
}

// ── Full report ──────────────────────────────────────────────────────────────

function formatFullReport(result) {
  const displayUrl = result.url.length > 32 ? result.url.substring(0, 32) + '..' : result.url;
  const lines = [];

  lines.push(header('Scan Report'));
  lines.push('');
  lines.push(kv('Target', displayUrl));
  lines.push(kv('Duration', result.duration + 's'));
  lines.push(kv('Timestamp', new Date(result.timestamp).toISOString().substring(0, 19) + 'Z'));
  lines.push('');

  // Risk block
  lines.push(subheader('Risk Assessment'));
  lines.push(kv('Overall Risk', riskStr(result.riskLevel)));
  lines.push(kv('Risk Score', result.riskScore + ' / 100'));
  lines.push(kv('Critical', result.summary.criticalCount));
  lines.push(kv('High', result.summary.highCount));
  lines.push(kv('Medium', result.summary.mediumCount));
  lines.push(kv('Low', result.summary.lowCount));
  lines.push('');

  // SSL
  lines.push(subheader('SSL / TLS'));
  lines.push(kv('HTTPS', statusStr(result.ssl.enabled)));
  lines.push(kv('Grade', result.ssl.grade || 'N/A'));
  if (result.ssl.hsts !== undefined) lines.push(kv('HSTS', statusStr(result.ssl.hsts)));
  if (result.ssl.httpRedirect !== undefined) lines.push(kv('HTTP Redirect', statusStr(result.ssl.httpRedirect)));
  if (result.ssl.issues && result.ssl.issues.length) {
    result.ssl.issues.slice(0, 3).forEach(i => lines.push(box('  ! ' + i.substring(0, 32))));
  }
  lines.push('');

  // Headers
  lines.push(subheader('Security Headers'));
  lines.push(kv('Score', result.headers.score + ' / 100'));
  lines.push(kv('Present', result.headers.presentHeaders.length + ' / 10'));
  lines.push(kv('Missing', result.headers.missingHeaders.length + ' / 10'));
  if (result.headers.server && result.headers.server !== 'Not disclosed') {
    lines.push(kv('Server', result.headers.server.substring(0, 18)));
  }
  if (result.headers.xPoweredBy) {
    lines.push(box('  ! X-Powered-By: ' + result.headers.xPoweredBy.substring(0, 18)));
  }
  if (result.headers.missingHeaders.length) {
    lines.push(box('  Missing:'));
    result.headers.missingHeaders.slice(0, 5).forEach(h => lines.push(box('    - ' + h.substring(0, 30))));
  }
  lines.push('');

  // SQLi
  lines.push(subheader('SQL Injection'));
  lines.push(kv('Status', result.sqli.vulnerable ? 'VULNERABLE' : 'SAFE'));
  lines.push(kv('Tests Run', result.sqli.tests.length + ' payloads'));
  if (result.sqli.vulnerable) {
    result.sqli.details.slice(0, 2).forEach(d => lines.push(box('  ! ' + d.substring(0, 32))));
  }
  lines.push('');

  // XSS
  lines.push(subheader('XSS'));
  lines.push(kv('Status', result.xss.vulnerable ? 'VULNERABLE' : 'SAFE'));
  lines.push(kv('Tests Run', result.xss.tests.length + ' payloads'));
  if (result.xss.vulnerable) {
    result.xss.details.slice(0, 2).forEach(d => lines.push(box('  ! ' + d.substring(0, 32))));
  }
  lines.push('');

  // CORS
  lines.push(subheader('CORS'));
  lines.push(kv('Status', result.cors.misconfigured ? 'MISCONFIGURED' : 'SAFE'));
  lines.push(kv('Allow-Origin', String(result.cors.allowOrigin || 'Not set').substring(0, 18)));
  if (result.cors.misconfigured) {
    result.cors.details.slice(0, 2).forEach(d => lines.push(box('  ! ' + d.substring(0, 32))));
  }
  lines.push('');

  // Redirect
  lines.push(subheader('Open Redirect'));
  lines.push(kv('Status', result.redirect.vulnerable ? 'VULNERABLE' : 'SAFE'));
  lines.push('');

  lines.push(rule(THICK));
  lines.push(boxCenter('SCAN COMPLETE'));
  lines.push(rule(THICK));

  return lines.join('\n');
}

// ── Headers-only report ──────────────────────────────────────────────────────

function formatHeadersReport(result) {
  return [
    header('Headers Report'),
    '',
    kv('Target', (result.url || '').substring(0, 28)),
    kv('HTTP Status', result.statusCode),
    kv('Server', (result.server || 'Unknown').substring(0, 18)),
    kv('Score', result.score + ' / 100'),
    '',
    rule(THIN),
    box(' Present headers:'),
    ...result.presentHeaders.map(h => box('  + ' + h.substring(0, 32))),
    '',
    box(' Missing headers:'),
    ...result.missingHeaders.map(h => box('  - ' + h.substring(0, 32))),
    result.xPoweredBy ? box('  ! X-Powered-By exposed: ' + result.xPoweredBy.substring(0, 12)) : '',
    '',
    rule(THICK),
  ].filter(Boolean).join('\n');
}

// ── SSL report ───────────────────────────────────────────────────────────────

function formatSslReport(result, url) {
  return [
    header('SSL/TLS Report'),
    '',
    kv('Target', url.substring(0, 28)),
    kv('HTTPS', statusStr(result.enabled)),
    kv('Grade', result.grade || 'N/A'),
    result.hsts !== undefined ? kv('HSTS', statusStr(result.hsts)) : '',
    result.httpRedirect !== undefined ? kv('HTTP Redirect', statusStr(result.httpRedirect)) : '',
    '',
    ...(result.issues && result.issues.length
      ? [rule(THIN), box(' Issues found:'), ...result.issues.map(i => box('  ! ' + i.substring(0, 32)))]
      : [rule(THIN), box(' No critical SSL issues detected.')]),
    '',
    rule(THICK),
  ].filter(Boolean).join('\n');
}

// ── Quick report ─────────────────────────────────────────────────────────────

function formatQuickReport(headerResult, sslResult) {
  return [
    header('Quick Scan Report'),
    '',
    kv('Target', (headerResult.url || '').substring(0, 28)),
    '',
    subheader('SSL / TLS'),
    kv('HTTPS', statusStr(sslResult.enabled)),
    kv('Grade', sslResult.grade || 'N/A'),
    sslResult.hsts !== undefined ? kv('HSTS', statusStr(sslResult.hsts)) : '',
    '',
    subheader('HTTP Headers'),
    kv('Score', headerResult.score + ' / 100'),
    kv('Present', headerResult.presentHeaders.length + ' / 10'),
    kv('Missing', headerResult.missingHeaders.length + ' / 10'),
    '',
    rule(THICK),
    boxCenter('SCAN COMPLETE'),
    rule(THICK),
  ].filter(Boolean).join('\n');
}

// ── Module info ──────────────────────────────────────────────────────────────

function moduleInfoMessage(mod) {
  const INFO = {
    sqli: {
      title: 'SQL Injection',
      risk: 'CRITICAL',
      desc: 'Sends crafted SQL payloads to URL parameters and detects error patterns indicating injection vulnerability.',
      vectors: ["'", "' OR 1=1--", '1; DROP TABLE--'],
    },
    xss: {
      title: 'XSS Scanner',
      risk: 'HIGH',
      desc: 'Injects script payloads into URL parameters and checks if the response reflects them unescaped.',
      vectors: ['<script>alert(1)</script>', '"><img src=x onerror=...>'],
    },
    headers: {
      title: 'Security Headers',
      risk: 'MEDIUM',
      desc: 'Checks for 10 standard HTTP security headers. Passive scan — no payloads sent.',
      vectors: ['Passive — no payloads'],
    },
    ssl: {
      title: 'SSL/TLS Check',
      risk: 'HIGH',
      desc: 'Verifies HTTPS, certificate validity, HSTS header, and HTTP-to-HTTPS redirect enforcement.',
      vectors: ['Passive — TLS handshake inspection'],
    },
    cors: {
      title: 'CORS Auditor',
      risk: 'HIGH',
      desc: 'Sends a spoofed Origin header and checks if the server reflects it in the response, indicating CORS misconfiguration.',
      vectors: ['Origin: https://evil-attacker.com'],
    },
    redirect: {
      title: 'Open Redirect',
      risk: 'MEDIUM',
      desc: 'Tests common redirect parameters for unvalidated redirection to external attacker-controlled domains.',
      vectors: ['?redirect=//evil.com', '?next=https://evil.com'],
    },
  };

  const m = INFO[mod];
  if (!m) return header('Unknown Module') + '\n\nModule not found.';

  return [
    header(m.title),
    '',
    kv('Risk Level', m.risk),
    '',
    rule(THIN),
    box(' Description:'),
    ...m.desc.match(/.{1,34}/g).map(l => box('  ' + l)),
    '',
    rule(THIN),
    box(' Test vectors:'),
    ...m.vectors.map(v => box('  - ' + v.substring(0, 32))),
    '',
    rule(THICK),
  ].join('\n');
}

// ── Settings ─────────────────────────────────────────────────────────────────

function settingsMessage() {
  return [
    header('Settings'),
    '',
    kv('Timeout', '10 seconds'),
    kv('Max Redirects', '5'),
    kv('User-Agent', 'VulnScan-Bot/1.0'),
    kv('Mode', 'Active + Passive'),
    kv('SSRF Guard', 'ENABLED'),
    kv('Webhook Auth', 'ENABLED'),
    '',
    rule(THIN),
    box(' SSRF protection blocks:'),
    box('  - 127.x / 10.x / 192.168.x'),
    box('  - 172.16-31.x / 169.254.x'),
    box('  - ::1 / fc00: / fe80:'),
    '',
    rule(THICK),
  ].join('\n');
}

// ── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  welcomeMessage,
  mainMenuMessage,
  helpMessage,
  aboutMessage,
  scanPromptMessage,
  scanningMessage,
  scanProgressMessage,
  formatFullReport,
  formatHeadersReport,
  formatSslReport,
  formatQuickReport,
  moduleInfoMessage,
  settingsMessage,
  STEPS,
  header,
  subheader,
  rule,
  box,
  kv,
  THIN,
  THICK,
};
