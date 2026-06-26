// Message templates for VulnScan Telegram Bot

// Escape user-supplied strings for Telegram Markdown v1
function escMd(str) {
  if (typeof str !== 'string') str = String(str);
  return str.replace(/_/g, '\\_').replace(/\*/g, '\\*');
}

function header(title) {
  const line = '\u2501'.repeat(38);
  return '`' + line + '`\n`  ' + title.toUpperCase().padEnd(36) + '`\n`' + line + '`';
}

function divider() {
  return '`' + '\u2500'.repeat(38) + '`';
}

function statusBadge(value) {
  if (value === true || value === 'PASS' || value === 'A' || value === 'OK') return '[  PASS  ]';
  if (value === false || value === 'FAIL' || value === 'F') return '[  FAIL  ]';
  if (value === 'WARN' || value === 'B') return '[  WARN  ]';
  return '[  INFO  ]';
}

function riskBadge(level) {
  const map = {
    CRITICAL: '[ CRITICAL ]',
    HIGH:     '[   HIGH   ]',
    MEDIUM:   '[  MEDIUM  ]',
    LOW:      '[   LOW    ]',
  };
  return map[level] || '[  UNKNOWN ]';
}

function welcomeMessage(firstName) {
  const name = escMd(firstName || 'User');
  return [
    header('VulnScan Bot'),
    '',
    'Welcome, *' + name + '*.',
    '',
    divider(),
    '`  PROFESSIONAL WEB SECURITY SCANNER   `',
    divider(),
    '',
    '*Available Modules:*',
    '`  SQL Injection Detection             `',
    '`  XSS Vulnerability Testing          `',
    '`  HTTP Security Headers Audit        `',
    '`  SSL/TLS Certificate Analysis       `',
    '`  CORS Misconfiguration Check        `',
    '`  Open Redirect Detection            `',
    '',
    divider(),
    '_Select an option from the menu below:_',
  ].join('\n');
}

function mainMenuMessage() {
  return [
    header('Main Menu'),
    '',
    '`  SCAN TARGET   ` - Run vulnerability scan',
    '`  QUICK SCAN    ` - Fast headers + SSL check',
    '`  FULL ANALYSIS ` - All modules combined',
    '`  REPORTS       ` - View saved scan reports',
    '`  MODULES       ` - Scanner module info',
    '`  HELP          ` - Usage instructions',
    '',
    divider(),
    '_Choose an option from the keyboard below._',
  ].join('\n');
}

function helpMessage() {
  return [
    header('Help & Usage'),
    '',
    '*How to scan a target:*',
    '1. Tap `[ SCAN TARGET ]` from the main menu',
    '2. Select a scan type',
    '3. Send the target URL when prompted',
    '4. Wait for results',
    '',
    divider(),
    '',
    '*Supported URL formats:*',
    '`  https://example.com              `',
    '`  http://example.com               `',
    '`  example.com  (auto-detects HTTPS)`',
    '',
    divider(),
    '',
    '*Scan types:*',
    '`  Full Scan    ` All modules combined',
    '`  Headers Only ` Security headers check',
    '`  SSL Check    ` Certificate validation',
    '`  SQLi Test    ` Injection detection',
    '`  XSS Test     ` Script injection check',
    '`  CORS Check   ` Cross-origin audit',
    '`  Redirect     ` Open redirect test',
    '',
    divider(),
    '',
    '*Commands:*',
    '`/start` - Show main menu',
    '`/scan <url>` - Quick full scan',
    '`/help` - Show this message',
    '`/cancel` - Cancel current operation',
  ].join('\n');
}

function aboutMessage() {
  return [
    header('About VulnScan'),
    '',
    '`  VulnScan Bot v1.0.0               `',
    '`  Professional Web Security Scanner  `',
    '',
    divider(),
    '',
    '*Purpose:*',
    'Automated reconnaissance and vulnerability',
    'assessment for web applications.',
    '',
    '*Disclaimer:*',
    '_Only scan targets you own or have explicit_',
    '_written permission to test. Unauthorized_',
    '_scanning is illegal._',
    '',
    divider(),
    '',
    '`  Built for security professionals    `',
  ].join('\n');
}

function scanPromptMessage(scanType) {
  const labels = {
    full: 'Full Scan (All Modules)',
    quick: 'Quick Scan (Headers + SSL)',
    headers: 'Headers Analysis',
    ssl: 'SSL/TLS Check',
    sqli: 'SQL Injection Test',
    xss: 'XSS Vulnerability Test',
    cors: 'CORS Audit',
    redirect: 'Open Redirect Test',
  };

  return [
    header('Target Input'),
    '',
    '*Module:* `' + (labels[scanType] || scanType) + '`',
    '',
    divider(),
    '',
    'Send the target URL to scan:',
    '',
    '`  Example: https://example.com       `',
    '`  Example: example.com               `',
    '',
    divider(),
    '_Type /cancel to abort._',
  ].join('\n');
}

function scanningMessage(url) {
  const safeUrl = url.length > 50 ? url.substring(0, 50) + '...' : url;
  return [
    header('Scanning...'),
    '',
    '*Target:* `' + safeUrl + '`',
    '',
    '`  [>>>>>>>>>>           ] 50%        `',
    '',
    '_Running vulnerability checks..._',
    '_Please wait, this may take 15-30 seconds._',
  ].join('\n');
}

function formatFullReport(result) {
  const lines = [];
  const displayUrl = result.url.length > 45 ? result.url.substring(0, 45) + '...' : result.url;

  lines.push(header('Scan Report'));
  lines.push('');
  lines.push('*Target:* `' + displayUrl + '`');
  lines.push('*Scanned:* `' + new Date(result.timestamp).toUTCString() + '`');
  lines.push('*Duration:* `' + result.duration + 's`');
  lines.push('');
  lines.push(divider());
  lines.push('');

  lines.push('*RISK ASSESSMENT*');
  lines.push('`  Overall Risk:  ' + riskBadge(result.riskLevel).padEnd(20) + '`');
  lines.push('`  Risk Score:    ' + String(result.riskScore + '/100').padEnd(20) + '`');
  lines.push('`  Critical:      ' + String(result.summary.criticalCount).padEnd(20) + '`');
  lines.push('`  High:          ' + String(result.summary.highCount).padEnd(20) + '`');
  lines.push('`  Medium:        ' + String(result.summary.mediumCount).padEnd(20) + '`');
  lines.push('`  Low:           ' + String(result.summary.lowCount).padEnd(20) + '`');
  lines.push('');
  lines.push(divider());
  lines.push('');

  lines.push('*SSL/TLS*');
  lines.push('`  HTTPS Enabled: ' + statusBadge(result.ssl.enabled).padEnd(20) + '`');
  lines.push('`  Grade:         ' + String(result.ssl.grade || 'N/A').padEnd(20) + '`');
  if (result.ssl.httpRedirect !== undefined) {
    lines.push('`  HTTP Redirect: ' + statusBadge(result.ssl.httpRedirect).padEnd(20) + '`');
  }
  if (result.ssl.issues && result.ssl.issues.length > 0) {
    for (const issue of result.ssl.issues) {
      lines.push('`  ! ' + issue.substring(0, 34) + '`');
    }
  }
  lines.push('');

  lines.push('*HTTP SECURITY HEADERS*');
  lines.push('`  Score:         ' + String(result.headers.score + '/100').padEnd(20) + '`');
  lines.push('`  Present:       ' + String(result.headers.presentHeaders.length).padEnd(20) + '`');
  lines.push('`  Missing:       ' + String(result.headers.missingHeaders.length).padEnd(20) + '`');
  if (result.headers.server && result.headers.server !== 'Not disclosed') {
    lines.push('`  Server:        ' + result.headers.server.substring(0, 20).padEnd(20) + '`');
  }
  if (result.headers.xPoweredBy) {
    lines.push('`  X-Powered-By:  ' + result.headers.xPoweredBy.substring(0, 20).padEnd(20) + '`');
  }
  lines.push('');
  lines.push('`  Missing Headers:                      `');
  for (const h of result.headers.missingHeaders.slice(0, 6)) {
    lines.push('`  - ' + h.substring(0, 35) + '`');
  }
  lines.push('');
  lines.push(divider());
  lines.push('');

  lines.push('*SQL INJECTION*');
  lines.push('`  Vulnerable:    ' + statusBadge(!result.sqli.vulnerable).padEnd(20) + '`');
  lines.push('`  Tests Run:     ' + String(result.sqli.tests.length).padEnd(20) + '`');
  if (result.sqli.vulnerable && result.sqli.details.length > 0) {
    lines.push('`  Findings:                            `');
    for (const d of result.sqli.details.slice(0, 2)) {
      lines.push('`  ! ' + d.substring(0, 34) + '`');
    }
  }
  lines.push('');

  lines.push('*XSS (CROSS-SITE SCRIPTING)*');
  lines.push('`  Vulnerable:    ' + statusBadge(!result.xss.vulnerable).padEnd(20) + '`');
  lines.push('`  Tests Run:     ' + String(result.xss.tests.length).padEnd(20) + '`');
  if (result.xss.vulnerable && result.xss.details.length > 0) {
    lines.push('`  Findings:                            `');
    for (const d of result.xss.details.slice(0, 2)) {
      lines.push('`  ! ' + d.substring(0, 34) + '`');
    }
  }
  lines.push('');

  lines.push('*CORS CONFIGURATION*');
  lines.push('`  Misconfigured: ' + statusBadge(!result.cors.misconfigured).padEnd(20) + '`');
  lines.push('`  Allow-Origin:  ' + String(result.cors.allowOrigin || 'Not set').substring(0, 20).padEnd(20) + '`');
  if (result.cors.misconfigured && result.cors.details.length > 0) {
    for (const d of result.cors.details) {
      lines.push('`  ! ' + d.substring(0, 34) + '`');
    }
  }
  lines.push('');

  lines.push('*OPEN REDIRECT*');
  lines.push('`  Vulnerable:    ' + statusBadge(!result.redirect.vulnerable).padEnd(20) + '`');
  lines.push('');
  lines.push(divider());
  lines.push('');
  lines.push('`  Scan Complete                        `');

  return lines.join('\n');
}

function formatHeadersReport(result) {
  const lines = [];
  lines.push(header('Headers Report'));
  lines.push('');
  lines.push('*Target:* `' + result.url + '`');
  lines.push('*Status Code:* `' + result.statusCode + '`');
  lines.push('*Server:* `' + (result.server || 'Unknown') + '`');
  lines.push('');
  lines.push(divider());
  lines.push('');
  lines.push('*Score: ' + result.score + '/100*');
  lines.push('');
  lines.push('`  HEADER                   STATUS    `');
  lines.push('`' + '\u2500'.repeat(38) + '`');

  for (const h of result.presentHeaders) {
    const label = h.replace('x-', '').replace(/-/g, ' ').toUpperCase().substring(0, 22).padEnd(22);
    lines.push('`  ' + label + '  [  PASS  ]  `');
  }
  for (const h of result.missingHeaders) {
    const label = h.replace('x-', '').replace(/-/g, ' ').toUpperCase().substring(0, 22).padEnd(22);
    lines.push('`  ' + label + '  MISSING    `');
  }

  if (result.xPoweredBy) {
    lines.push('');
    lines.push('_Warning: X-Powered-By header exposes: ' + result.xPoweredBy + '_');
  }

  return lines.join('\n');
}

function formatSslReport(result, url) {
  const lines = [];
  lines.push(header('SSL/TLS Report'));
  lines.push('');
  lines.push('*Target:* `' + url + '`');
  lines.push('');
  lines.push(divider());
  lines.push('');
  lines.push('`  HTTPS Enabled:   ' + statusBadge(result.enabled).padEnd(18) + '`');
  lines.push('`  Security Grade:  ' + ('[ ' + result.grade + ' ]').padEnd(18) + '`');

  if (result.httpRedirect !== undefined) {
    lines.push('`  HTTP->HTTPS:     ' + statusBadge(result.httpRedirect).padEnd(18) + '`');
  }
  if (result.hsts !== undefined) {
    lines.push('`  HSTS Header:     ' + statusBadge(result.hsts).padEnd(18) + '`');
  }

  if (result.issues && result.issues.length > 0) {
    lines.push('');
    lines.push('*Issues Found:*');
    for (const issue of result.issues) {
      lines.push('`  ! ' + issue + '`');
    }
  } else {
    lines.push('');
    lines.push('_No critical SSL issues detected._');
  }

  return lines.join('\n');
}

function formatQuickReport(headerResult, sslResult) {
  const lines = [];
  lines.push(header('Quick Scan Report'));
  lines.push('');
  lines.push('*Target:* `' + headerResult.url + '`');
  lines.push('');
  lines.push(divider());
  lines.push('');
  lines.push('*SSL/TLS*');
  lines.push('`  Grade:    ' + ('[ ' + sslResult.grade + ' ]').padEnd(26) + '`');
  lines.push('`  HTTPS:    ' + statusBadge(sslResult.enabled).padEnd(26) + '`');
  lines.push('');
  lines.push('*HTTP Headers*');
  lines.push('`  Score:    ' + String(headerResult.score + '/100').padEnd(26) + '`');
  lines.push('`  Present:  ' + String(headerResult.presentHeaders.length).padEnd(26) + '`');
  lines.push('`  Missing:  ' + String(headerResult.missingHeaders.length).padEnd(26) + '`');

  return lines.join('\n');
}

function moduleInfoMessage(module) {
  const info = {
    sqli: {
      title: 'SQL Injection Scanner',
      desc: 'Tests for SQL injection vulnerabilities by sending crafted payloads to URL parameters and analyzing error responses from the target.',
      payloads: ["'", '"', "' OR 1=1--"],
      risk: 'CRITICAL',
    },
    xss: {
      title: 'XSS Scanner',
      desc: 'Tests for reflected Cross-Site Scripting by injecting script payloads and checking if they are returned unencoded in the response.',
      payloads: ['<script>alert(1)</script>', '"><img src=x onerror=...>'],
      risk: 'HIGH',
    },
    headers: {
      title: 'Security Headers Analyzer',
      desc: 'Checks for the presence and configuration of HTTP security headers that protect against common web attacks.',
      payloads: ['None - passive check only'],
      risk: 'MEDIUM',
    },
    ssl: {
      title: 'SSL/TLS Checker',
      desc: 'Verifies HTTPS usage, TLS certificate validity, HSTS header, and HTTP-to-HTTPS redirect enforcement.',
      payloads: ['None - passive check only'],
      risk: 'HIGH',
    },
    cors: {
      title: 'CORS Auditor',
      desc: 'Sends a request with a malicious Origin header to check if the server reflects it back, indicating a CORS misconfiguration.',
      payloads: ['Origin: https://evil-attacker.com'],
      risk: 'HIGH',
    },
    redirect: {
      title: 'Open Redirect Detector',
      desc: 'Tests if the application follows redirect parameters to external domains, which can be used for phishing.',
      payloads: ['?redirect=//evil.com', '?next=https://evil.com'],
      risk: 'MEDIUM',
    },
  };

  const m = info[module];
  if (!m) return 'Module not found.';

  return [
    header(m.title),
    '',
    '*Description:*',
    m.desc,
    '',
    divider(),
    '',
    '*Risk Level:* `' + m.risk + '`',
    '',
    '*Test Vectors:*',
    ...m.payloads.map(p => '`  ' + p.substring(0, 35) + '`'),
  ].join('\n');
}

module.exports = {
  welcomeMessage,
  mainMenuMessage,
  helpMessage,
  aboutMessage,
  scanPromptMessage,
  scanningMessage,
  formatFullReport,
  formatHeadersReport,
  formatSslReport,
  formatQuickReport,
  moduleInfoMessage,
  header,
  divider,
};
