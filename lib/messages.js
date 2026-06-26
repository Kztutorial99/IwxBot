// IwxBot Messages v3 — no ASCII borders, native Telegram formatting

function escMd(str) {
  if (typeof str !== 'string') str = String(str);
  return str.replace(/_/g, '\\_').replace(/\*/g, '\\*');
}

// ── Progress bar (text only, no borders) ─────────────────────────────────────

const STEPS = [
  { pct:  5, label: 'Initializing scan' },
  { pct: 20, label: 'Checking SSL/TLS certificate' },
  { pct: 38, label: 'Auditing HTTP security headers' },
  { pct: 55, label: 'Testing SQL injection vectors' },
  { pct: 70, label: 'Testing XSS vulnerabilities' },
  { pct: 82, label: 'Auditing CORS configuration' },
  { pct: 92, label: 'Testing open redirect vectors' },
  { pct: 100, label: 'Compiling report' },
];

function progressBar(pct) {
  const filled = Math.round(pct / 100 * 16);
  return '[' + '#'.repeat(filled) + '.'.repeat(16 - filled) + '] ' + String(pct).padStart(3) + '%';
}

function scanProgressMessage(url, stepIndex) {
  const step = STEPS[Math.min(stepIndex, STEPS.length - 1)];
  const display = url.length > 40 ? url.substring(0, 40) + '...' : url;
  return [
    '*[ SCANNING ]*',
    '',
    '`' + progressBar(step.pct) + '`',
    '_' + step.label + '..._',
    '',
    '*Target*',
    '`' + display + '`',
  ].join('\n');
}

function scanningMessage(url) {
  return scanProgressMessage(url, 0);
}

// ── Welcome ──────────────────────────────────────────────────────────────────

function welcomeMessage(firstName) {
  const name = escMd(firstName || 'Operator');
  return [
    '*IwxBot* — Web Vulnerability Scanner',
    '',
    'Hello, *' + name + '*. Ready to scan.',
    '',
    '*Modules*',
    '`SQLi  ` SQL Injection Detection',
    '`XSS   ` Cross-Site Scripting',
    '`HDR   ` HTTP Security Headers',
    '`SSL   ` TLS Certificate Audit',
    '`CORS  ` Misconfiguration Check',
    '`REDIR ` Open Redirect Detection',
    '',
    '_Select an option from the menu below._',
  ].join('\n');
}

// ── Main menu ─────────────────────────────────────────────────────────────────

function mainMenuMessage() {
  return [
    '*IwxBot* — Main Menu',
    '',
    '`SCAN     ` Run vulnerability scan',
    '`QUICK    ` Fast headers + SSL check',
    '`FULL     ` All 6 modules combined',
    '`MODULES  ` About scanner modules',
    '`SETTINGS ` Bot configuration',
    '`HELP     ` Usage guide',
  ].join('\n');
}

// ── Help ──────────────────────────────────────────────────────────────────────

function helpMessage() {
  return [
    '*IwxBot Help*',
    '',
    '*Commands*',
    '`/start` — Main menu',
    '`/scan <url>` — Full scan',
    '`/help` — This message',
    '`/cancel` — Abort scan',
    '',
    '*Supported URLs*',
    '`https://example.com`',
    '`http://example.com`',
    '`example.com` _(auto-HTTPS)_',
    '',
    '*Scan Modules*',
    '`Full   ` All 6 modules',
    '`Quick  ` Headers + SSL',
    '`SQLi   ` SQL injection',
    '`XSS    ` Script injection',
    '`CORS   ` Cross-origin',
    '`SSL    ` TLS certificate',
    '`Redir  ` Open redirect',
    '',
    '_Only scan targets you own or have_',
    '_explicit permission to test._',
  ].join('\n');
}

// ── About ─────────────────────────────────────────────────────────────────────

function aboutMessage() {
  return [
    '*IwxBot v2.0*',
    '_Web Vulnerability Scanner_',
    '',
    '`Version  ` 2.0.0',
    '`Author   ` Kztutorial99',
    '`Deploy   ` Vercel Serverless',
    '`GitHub   ` Kztutorial99/IwxBot',
    '',
    '*Scanner Modules*',
    '`SQLi   ` Error-based injection detection',
    '`XSS    ` Reflected payload check',
    '`Headers` 10 security headers audit',
    '`SSL    ` TLS + HSTS + redirect check',
    '`CORS   ` Origin spoofing test',
    '`Redirect` Open redirect vectors',
    '',
    '_Unauthorized scanning is illegal._',
  ].join('\n');
}

// ── Scan prompt ───────────────────────────────────────────────────────────────

function scanPromptMessage(scanType) {
  const labels = {
    full:     'Full Scan — All 6 Modules',
    quick:    'Quick Scan — Headers + SSL',
    headers:  'Headers Analysis',
    ssl:      'SSL/TLS Check',
    sqli:     'SQL Injection Test',
    xss:      'XSS Vulnerability Test',
    cors:     'CORS Audit',
    redirect: 'Open Redirect Test',
  };
  return [
    '*[ ' + (labels[scanType] || scanType).toUpperCase() + ' ]*',
    '',
    'Send the target URL:',
    '`https://example.com`',
    '',
    '_/cancel to abort_',
  ].join('\n');
}

// ── Risk label ────────────────────────────────────────────────────────────────

function riskLabel(level) {
  return { CRITICAL: 'CRITICAL', HIGH: 'HIGH', MEDIUM: 'MEDIUM', LOW: 'LOW' }[level] || 'UNKNOWN';
}

function statusLabel(val) {
  if (val === true  || val === 'PASS') return 'PASS';
  if (val === false || val === 'FAIL') return 'FAIL';
  if (val === 'WARN')                  return 'WARN';
  return String(val);
}

// ── Full report ───────────────────────────────────────────────────────────────

function formatFullReport(result) {
  const url = result.url.length > 38 ? result.url.substring(0, 38) + '..' : result.url;
  const lines = [];

  lines.push('*Scan Report*');
  lines.push('');
  lines.push('`Target   ` `' + url + '`');
  lines.push('`Duration ` ' + result.duration + 's');
  lines.push('');

  // Risk
  lines.push('*Risk Assessment*');
  lines.push('`Risk    ` *' + riskLabel(result.riskLevel) + '*  `' + result.riskScore + '/100`');
  if (result.summary.criticalCount) lines.push('`Critical` ' + result.summary.criticalCount);
  if (result.summary.highCount)     lines.push('`High    ` ' + result.summary.highCount);
  if (result.summary.mediumCount)   lines.push('`Medium  ` ' + result.summary.mediumCount);
  if (result.summary.lowCount)      lines.push('`Low     ` ' + result.summary.lowCount);
  lines.push('');

  // SSL
  lines.push('*SSL / TLS*');
  lines.push('`HTTPS   ` ' + statusLabel(result.ssl.enabled));
  lines.push('`Grade   ` ' + (result.ssl.grade || 'N/A'));
  if (result.ssl.hsts !== undefined)         lines.push('`HSTS    ` ' + statusLabel(result.ssl.hsts));
  if (result.ssl.httpRedirect !== undefined) lines.push('`Redirect` ' + statusLabel(result.ssl.httpRedirect));
  if (result.ssl.issues && result.ssl.issues.length) {
    result.ssl.issues.slice(0, 2).forEach(i => lines.push('`!       ` _' + i.substring(0, 36) + '_'));
  }
  lines.push('');

  // Headers
  lines.push('*HTTP Headers*');
  lines.push('`Score   ` ' + result.headers.score + '/100  `' + result.headers.presentHeaders.length + '/10 present`');
  if (result.headers.server && result.headers.server !== 'Not disclosed') {
    lines.push('`Server  ` `' + result.headers.server.substring(0, 22) + '`');
  }
  if (result.headers.xPoweredBy) {
    lines.push('`!       ` X-Powered-By exposed: `' + result.headers.xPoweredBy.substring(0, 16) + '`');
  }
  if (result.headers.missingHeaders.length) {
    lines.push('_Missing: ' + result.headers.missingHeaders.slice(0, 4).join(', ') + '_');
  }
  lines.push('');

  // SQLi
  lines.push('*SQL Injection*');
  lines.push('`Status  ` ' + (result.sqli.vulnerable ? '*VULNERABLE*' : 'SAFE'));
  lines.push('`Tests   ` ' + result.sqli.tests.length + ' payloads');
  if (result.sqli.vulnerable) {
    result.sqli.details.slice(0, 1).forEach(d => lines.push('`!       ` _' + d.substring(0, 36) + '_'));
  }
  lines.push('');

  // XSS
  lines.push('*XSS*');
  lines.push('`Status  ` ' + (result.xss.vulnerable ? '*VULNERABLE*' : 'SAFE'));
  lines.push('`Tests   ` ' + result.xss.tests.length + ' payloads');
  if (result.xss.vulnerable) {
    result.xss.details.slice(0, 1).forEach(d => lines.push('`!       ` _' + d.substring(0, 36) + '_'));
  }
  lines.push('');

  // CORS
  lines.push('*CORS*');
  lines.push('`Status  ` ' + (result.cors.misconfigured ? '*MISCONFIGURED*' : 'SAFE'));
  lines.push('`Origin  ` ' + String(result.cors.allowOrigin || 'Not set').substring(0, 24));
  lines.push('');

  // Redirect
  lines.push('*Open Redirect*');
  lines.push('`Status  ` ' + (result.redirect.vulnerable ? '*VULNERABLE*' : 'SAFE'));
  lines.push('');

  lines.push('_Scan complete._');

  return lines.join('\n');
}

// ── Headers report ────────────────────────────────────────────────────────────

function formatHeadersReport(result) {
  return [
    '*Headers Report*',
    '',
    '`Target ` `' + (result.url || '').substring(0, 34) + '`',
    '`Status ` ' + result.statusCode,
    '`Score  ` ' + result.score + '/100',
    '`Server ` ' + (result.server || 'Unknown').substring(0, 24),
    '',
    '*Present*',
    result.presentHeaders.map(h => '`+` ' + h).join('\n'),
    '',
    '*Missing*',
    result.missingHeaders.map(h => '`-` ' + h).join('\n'),
    result.xPoweredBy ? '\n`!` X-Powered-By: `' + result.xPoweredBy.substring(0, 20) + '`' : '',
  ].filter(s => s !== '').join('\n');
}

// ── SSL report ────────────────────────────────────────────────────────────────

function formatSslReport(result, url) {
  const lines = [
    '*SSL/TLS Report*',
    '',
    '`Target   ` `' + url.substring(0, 34) + '`',
    '`HTTPS    ` ' + statusLabel(result.enabled),
    '`Grade    ` ' + (result.grade || 'N/A'),
  ];
  if (result.hsts !== undefined)         lines.push('`HSTS     ` ' + statusLabel(result.hsts));
  if (result.httpRedirect !== undefined) lines.push('`Redirect ` ' + statusLabel(result.httpRedirect));
  if (result.issues && result.issues.length) {
    lines.push('');
    lines.push('*Issues*');
    result.issues.forEach(i => lines.push('`!` _' + i + '_'));
  } else {
    lines.push('');
    lines.push('_No critical SSL issues._');
  }
  return lines.join('\n');
}

// ── Quick report ──────────────────────────────────────────────────────────────

function formatQuickReport(headerResult, sslResult) {
  return [
    '*Quick Scan Report*',
    '',
    '`Target  ` `' + (headerResult.url || '').substring(0, 34) + '`',
    '',
    '*SSL/TLS*',
    '`HTTPS   ` ' + statusLabel(sslResult.enabled),
    '`Grade   ` ' + (sslResult.grade || 'N/A'),
    sslResult.hsts !== undefined ? '`HSTS    ` ' + statusLabel(sslResult.hsts) : '',
    '',
    '*HTTP Headers*',
    '`Score   ` ' + headerResult.score + '/100',
    '`Present ` ' + headerResult.presentHeaders.length + '/10',
    '`Missing ` ' + headerResult.missingHeaders.length + '/10',
    '',
    '_Scan complete._',
  ].filter(s => s !== null && s !== undefined).join('\n');
}

// ── Module info ───────────────────────────────────────────────────────────────

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
      desc: 'Checks for 10 standard HTTP security headers. Passive scan, no payloads sent.',
      vectors: ['Passive — no payloads'],
    },
    ssl: {
      title: 'SSL/TLS Check',
      risk: 'HIGH',
      desc: 'Verifies HTTPS, certificate validity, HSTS header, and HTTP-to-HTTPS redirect.',
      vectors: ['Passive — TLS handshake only'],
    },
    cors: {
      title: 'CORS Auditor',
      risk: 'HIGH',
      desc: 'Sends a spoofed Origin header and checks if the server reflects it back.',
      vectors: ['Origin: https://evil-attacker.com'],
    },
    redirect: {
      title: 'Open Redirect',
      risk: 'MEDIUM',
      desc: 'Tests common redirect parameters for unvalidated external redirection.',
      vectors: ['?redirect=//evil.com', '?next=https://evil.com'],
    },
  };

  const m = INFO[mod];
  if (!m) return '*Unknown Module*\n\nModule not found.';

  return [
    '*' + m.title + '*',
    '`Risk ` ' + m.risk,
    '',
    m.desc,
    '',
    '*Test Vectors*',
    ...m.vectors.map(v => '`' + v.substring(0, 36) + '`'),
  ].join('\n');
}

// ── Settings ──────────────────────────────────────────────────────────────────

function settingsMessage() {
  return [
    '*IwxBot Settings*',
    '',
    '`Timeout      ` 10 seconds',
    '`Max Redirects` 5',
    '`Scan Mode    ` Active + Passive',
    '`SSRF Guard   ` ENABLED',
    '`Webhook Auth ` ENABLED',
    '',
    '*SSRF Protection*',
    '_Blocks: 127.x, 10.x, 192.168.x,_',
    '_172.16-31.x, 169.254.x, ::1_',
  ].join('\n');
}

// ── Exports ───────────────────────────────────────────────────────────────────

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
};
