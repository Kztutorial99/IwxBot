const axios = require('axios');

const DEFAULT_TIMEOUT = 10000;

const SECURITY_HEADERS = [
  'x-frame-options',
  'x-content-type-options',
  'x-xss-protection',
  'strict-transport-security',
  'content-security-policy',
  'referrer-policy',
  'permissions-policy',
  'cross-origin-opener-policy',
  'cross-origin-resource-policy',
  'cross-origin-embedder-policy',
];

const SQL_PAYLOADS = ["'", '"', "' OR '1'='1", "1; DROP TABLE users--", "' OR 1=1--"];
const XSS_PAYLOADS = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', "';alert(1)//"];

function normalizeUrl(url) {
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    return 'https://' + url;
  }
  return url;
}

async function checkHttpHeaders(url) {
  const result = {
    url,
    statusCode: null,
    server: null,
    headers: {},
    missingHeaders: [],
    presentHeaders: [],
    score: 0,
    redirects: [],
  };

  try {
    const response = await axios.get(url, {
      timeout: DEFAULT_TIMEOUT,
      maxRedirects: 5,
      validateStatus: () => true,
      headers: { 'User-Agent': 'VulnScan-Bot/1.0 (Security Audit Tool)' },
    });

    result.statusCode = response.status;
    result.server = response.headers['server'] || 'Not disclosed';
    result.headers = response.headers;

    for (const header of SECURITY_HEADERS) {
      if (response.headers[header]) {
        result.presentHeaders.push(header);
        result.score += 10;
      } else {
        result.missingHeaders.push(header);
      }
    }

    // Check for information disclosure
    result.xPoweredBy = response.headers['x-powered-by'] || null;
    result.via = response.headers['via'] || null;

  } catch (err) {
    result.error = err.message;
  }

  return result;
}

async function checkSsl(url) {
  const result = {
    enabled: false,
    grade: 'F',
    issues: [],
    info: {},
  };

  try {
    const parsed = new URL(url);
    if (parsed.protocol === 'https:') {
      result.enabled = true;
      result.grade = 'A';

      // Try HTTP to see if redirect exists
      const httpUrl = url.replace('https://', 'http://');
      try {
        const httpResp = await axios.get(httpUrl, {
          timeout: DEFAULT_TIMEOUT,
          maxRedirects: 0,
          validateStatus: () => true,
        });
        if (httpResp.status >= 300 && httpResp.status < 400) {
          result.httpRedirect = true;
        } else {
          result.httpRedirect = false;
          result.issues.push('HTTP does not redirect to HTTPS');
          result.grade = 'B';
        }
      } catch {
        result.httpRedirect = true;
      }

    } else {
      result.issues.push('Site does not use HTTPS');
      result.grade = 'F';
    }
  } catch (err) {
    result.error = err.message;
  }

  return result;
}

async function checkSqlInjection(url) {
  const result = {
    vulnerable: false,
    tests: [],
    details: [],
  };

  const errorPatterns = [
    /sql syntax/i,
    /mysql_fetch/i,
    /ORA-\d{5}/i,
    /PostgreSQL.*ERROR/i,
    /SQLite.*error/i,
    /Microsoft SQL/i,
    /ODBC Driver/i,
    /Unclosed quotation/i,
    /quoted string not properly terminated/i,
    /syntax error.*SQL/i,
  ];

  for (const payload of SQL_PAYLOADS.slice(0, 3)) {
    const testUrl = `${url}?id=${encodeURIComponent(payload)}&q=${encodeURIComponent(payload)}`;
    const test = { payload, url: testUrl, vulnerable: false };

    try {
      const resp = await axios.get(testUrl, {
        timeout: DEFAULT_TIMEOUT,
        validateStatus: () => true,
        headers: { 'User-Agent': 'VulnScan-Bot/1.0' },
      });

      for (const pattern of errorPatterns) {
        if (pattern.test(resp.data)) {
          test.vulnerable = true;
          test.pattern = pattern.toString();
          result.vulnerable = true;
          result.details.push(`SQL error pattern detected with payload: ${payload}`);
          break;
        }
      }
    } catch {
      test.error = 'Request failed';
    }

    result.tests.push(test);
  }

  return result;
}

async function checkXss(url) {
  const result = {
    vulnerable: false,
    tests: [],
    details: [],
  };

  for (const payload of XSS_PAYLOADS.slice(0, 2)) {
    const testUrl = `${url}?q=${encodeURIComponent(payload)}&search=${encodeURIComponent(payload)}`;
    const test = { payload, vulnerable: false };

    try {
      const resp = await axios.get(testUrl, {
        timeout: DEFAULT_TIMEOUT,
        validateStatus: () => true,
        headers: { 'User-Agent': 'VulnScan-Bot/1.0' },
      });

      if (resp.data && resp.data.includes(payload)) {
        test.vulnerable = true;
        result.vulnerable = true;
        result.details.push(`XSS payload reflected in response: ${payload.substring(0, 30)}`);
      }

      // Check CSP header
      if (!resp.headers['content-security-policy']) {
        test.noCSP = true;
      }
    } catch {
      test.error = 'Request failed';
    }

    result.tests.push(test);
  }

  return result;
}

async function checkCors(url) {
  const result = {
    misconfigured: false,
    details: [],
  };

  try {
    const resp = await axios.get(url, {
      timeout: DEFAULT_TIMEOUT,
      validateStatus: () => true,
      headers: {
        'Origin': 'https://evil-attacker.com',
        'User-Agent': 'VulnScan-Bot/1.0',
      },
    });

    const acao = resp.headers['access-control-allow-origin'];
    const acac = resp.headers['access-control-allow-credentials'];

    if (acao === '*') {
      result.misconfigured = false;
      result.details.push('Wildcard CORS - public API (acceptable)');
      result.allowOrigin = '*';
    } else if (acao === 'https://evil-attacker.com') {
      result.misconfigured = true;
      result.details.push('CRITICAL: Reflects arbitrary Origin header');
      result.allowOrigin = acao;
    } else if (acao && acac === 'true') {
      result.misconfigured = true;
      result.details.push('CORS allows credentials with specific origin');
      result.allowOrigin = acao;
    } else {
      result.details.push('CORS not enabled or properly restricted');
      result.allowOrigin = acao || 'Not set';
    }

  } catch (err) {
    result.error = err.message;
  }

  return result;
}

async function checkOpenRedirect(url) {
  const result = {
    vulnerable: false,
    tests: [],
  };

  const redirectPayloads = [
    '//evil.com',
    'https://evil.com',
    '/\\evil.com',
  ];

  for (const payload of redirectPayloads.slice(0, 2)) {
    const testUrl = `${url}?redirect=${encodeURIComponent(payload)}&next=${encodeURIComponent(payload)}&url=${encodeURIComponent(payload)}`;
    const test = { payload, vulnerable: false };

    try {
      const resp = await axios.get(testUrl, {
        timeout: DEFAULT_TIMEOUT,
        maxRedirects: 0,
        validateStatus: () => true,
        headers: { 'User-Agent': 'VulnScan-Bot/1.0' },
      });

      if ((resp.status >= 300 && resp.status < 400) && resp.headers.location) {
        const loc = resp.headers.location;
        if (loc.includes('evil.com')) {
          test.vulnerable = true;
          test.location = loc;
          result.vulnerable = true;
        }
      }
    } catch {
      test.error = 'Request failed';
    }

    result.tests.push(test);
  }

  return result;
}

async function fullScan(targetUrl) {
  const url = normalizeUrl(targetUrl);
  const startTime = Date.now();

  const [headers, ssl, sqli, xss, cors, redirect] = await Promise.all([
    checkHttpHeaders(url),
    checkSsl(url),
    checkSqlInjection(url),
    checkXss(url),
    checkCors(url),
    checkOpenRedirect(url),
  ]);

  const duration = ((Date.now() - startTime) / 1000).toFixed(2);

  // Calculate risk score
  let riskScore = 0;
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;

  if (sqli.vulnerable) { riskScore += 40; criticalCount++; }
  if (xss.vulnerable) { riskScore += 30; highCount++; }
  if (cors.misconfigured) { riskScore += 25; highCount++; }
  if (redirect.vulnerable) { riskScore += 20; mediumCount++; }
  if (ssl.grade === 'F') { riskScore += 30; highCount++; }
  if (headers.missingHeaders.length > 5) { riskScore += 15; mediumCount++; }
  else if (headers.missingHeaders.length > 2) { riskScore += 8; lowCount++; }

  const riskLevel = riskScore >= 60 ? 'CRITICAL' :
                    riskScore >= 40 ? 'HIGH' :
                    riskScore >= 20 ? 'MEDIUM' : 'LOW';

  return {
    url,
    timestamp: new Date().toISOString(),
    duration,
    riskScore,
    riskLevel,
    summary: { criticalCount, highCount, mediumCount, lowCount },
    headers,
    ssl,
    sqli,
    xss,
    cors,
    redirect,
  };
}

module.exports = { fullScan, checkHttpHeaders, checkSsl, checkSqlInjection, checkXss, checkCors, checkOpenRedirect, normalizeUrl };
