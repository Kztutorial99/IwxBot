// IwxBot — Vercel Serverless Webhook v3
// Fast: all scan modules run in parallel, progress bar updates async
const https = require('https');

const TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || '';

// ── Telegram API ──────────────────────────────────────────────────────────────

function tg(method, body) {
  return new Promise((resolve) => {
    const data = JSON.stringify(body);
    const req = https.request({
      hostname: 'api.telegram.org',
      path: `/bot${TOKEN}/${method}`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
    }, (res) => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => { try { resolve(JSON.parse(raw)); } catch { resolve({}); } });
    });
    req.on('error', () => resolve({}));
    req.write(data);
    req.end();
  });
}

const sendMsg = (chat_id, text, extra = {}) =>
  tg('sendMessage', { chat_id, text, parse_mode: 'Markdown', ...extra });

const editMsg = (chat_id, message_id, text, extra = {}) =>
  tg('editMessageText', { chat_id, message_id, text, parse_mode: 'Markdown', ...extra });

const answerCB = (callback_query_id) =>
  tg('answerCallbackQuery', { callback_query_id });

// ── Modules ───────────────────────────────────────────────────────────────────

const scanner = require('../lib/scanner');
const { mainMenu, scanMenu, modulesMenu, backToMain, backOnly } = require('../lib/keyboards');
const msg = require('../lib/messages');

// ── Sessions ──────────────────────────────────────────────────────────────────

const sessions = {};
const getSession   = id => sessions[id] || (sessions[id] = { state: 'idle', scanType: null });
const setSession   = (id, d) => { sessions[id] = { ...getSession(id), ...d }; };
const clearSession = id => { sessions[id] = { state: 'idle', scanType: null }; };

const normalizeUrl = s => s.startsWith('http') ? s : 'https://' + s;
function isValidUrl(s) {
  try { new URL(normalizeUrl(s)); return true; } catch { return false; }
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

// ── Fast parallel full scan ───────────────────────────────────────────────────
// All 6 modules fire at once; progress bar updates independently

async function runFastFullScan(chatId, msgId, url) {
  // Fire all modules in parallel immediately
  const [sslP, headersP, sqliP, xssP, corsP, redirectP] = [
    scanner.checkSsl(url).catch(() => ({ enabled: false, grade: 'F', issues: ['Timeout'] })),
    scanner.checkHttpHeaders(url).catch(() => ({ url, score: 0, server: 'N/A', presentHeaders: [], missingHeaders: [], statusCode: 0 })),
    scanner.checkSqlInjection(url).catch(() => ({ vulnerable: false, tests: [], details: [] })),
    scanner.checkXss(url).catch(() => ({ vulnerable: false, tests: [], details: [] })),
    scanner.checkCors(url).catch(() => ({ misconfigured: false, details: [], allowOrigin: 'N/A' })),
    scanner.checkOpenRedirect(url).catch(() => ({ vulnerable: false, tests: [] })),
  ];

  // Animate progress bar while modules resolve in background
  const progressSteps = [1, 2, 3, 4, 5, 6, 7];
  let step = 0;
  const animate = setInterval(async () => {
    if (step < progressSteps.length) {
      await editMsg(chatId, msgId, msg.scanProgressMessage(url, progressSteps[step])).catch(() => {});
      step++;
    }
  }, 800);

  // Wait for all modules
  const [ssl, headers, sqli, xss, cors, redirect] = await Promise.all([sslP, headersP, sqliP, xssP, corsP, redirectP]);
  clearInterval(animate);

  headers.url = url;

  // Calculate risk
  let riskScore = 0, criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0;
  if (sqli.vulnerable)                       { riskScore += 40; criticalCount++; }
  if (xss.vulnerable)                        { riskScore += 30; highCount++; }
  if (cors.misconfigured)                    { riskScore += 25; highCount++; }
  if (redirect.vulnerable)                   { riskScore += 20; mediumCount++; }
  if (ssl.grade === 'F')                     { riskScore += 30; highCount++; }
  if (headers.missingHeaders.length > 5)    { riskScore += 15; mediumCount++; }
  else if (headers.missingHeaders.length > 2) { riskScore += 8; lowCount++; }

  const riskLevel = riskScore >= 60 ? 'CRITICAL'
                  : riskScore >= 40 ? 'HIGH'
                  : riskScore >= 20 ? 'MEDIUM' : 'LOW';

  return {
    url,
    timestamp: new Date().toISOString(),
    duration: '~',
    riskScore: Math.min(riskScore, 100),
    riskLevel,
    summary: { criticalCount, highCount, mediumCount, lowCount },
    headers, ssl, sqli, xss, cors, redirect,
  };
}

// ── Single module scan ────────────────────────────────────────────────────────

async function runModuleScan(chatId, msgId, url, scanType) {
  // Show progress step 1 immediately
  await editMsg(chatId, msgId, msg.scanProgressMessage(url, 1));

  let reportText;
  if (scanType === 'quick') {
    const [h, s] = await Promise.all([
      scanner.checkHttpHeaders(url).catch(() => ({ url, score: 0, presentHeaders: [], missingHeaders: [] })),
      scanner.checkSsl(url).catch(() => ({ enabled: false, grade: 'F', issues: [] })),
    ]);
    h.url = url;
    reportText = msg.formatQuickReport(h, s);

  } else if (scanType === 'headers') {
    const r = await scanner.checkHttpHeaders(url);
    r.url = url;
    reportText = msg.formatHeadersReport(r);

  } else if (scanType === 'ssl') {
    const r = await scanner.checkSsl(url);
    reportText = msg.formatSslReport(r, url);

  } else if (scanType === 'sqli') {
    const r = await scanner.checkSqlInjection(url);
    const status = r.vulnerable ? '*VULNERABLE*' : 'SAFE';
    reportText = [
      '*SQL Injection Report*', '',
      '`Target ` `' + url.substring(0, 34) + '`',
      '`Status ` ' + status,
      '`Tests  ` ' + r.tests.length + ' payloads',
      '',
      r.vulnerable
        ? r.details.map(d => '`!` _' + d.substring(0, 36) + '_').join('\n')
        : '_No SQL error patterns detected._',
    ].join('\n');

  } else if (scanType === 'xss') {
    const r = await scanner.checkXss(url);
    const status = r.vulnerable ? '*VULNERABLE*' : 'SAFE';
    reportText = [
      '*XSS Scan Report*', '',
      '`Target ` `' + url.substring(0, 34) + '`',
      '`Status ` ' + status,
      '`Tests  ` ' + r.tests.length + ' payloads',
      '',
      r.vulnerable
        ? r.details.map(d => '`!` _' + d.substring(0, 36) + '_').join('\n')
        : '_No reflected XSS detected._',
    ].join('\n');

  } else if (scanType === 'cors') {
    const r = await scanner.checkCors(url);
    reportText = [
      '*CORS Audit Report*', '',
      '`Target  ` `' + url.substring(0, 34) + '`',
      '`Status  ` ' + (r.misconfigured ? '*MISCONFIGURED*' : 'SAFE'),
      '`Origin  ` ' + String(r.allowOrigin || 'Not set').substring(0, 24),
      '',
      r.details.length ? r.details.map(d => '`!` _' + d.substring(0, 36) + '_').join('\n') : '_CORS properly configured._',
    ].join('\n');

  } else if (scanType === 'redirect') {
    const r = await scanner.checkOpenRedirect(url);
    reportText = [
      '*Open Redirect Report*', '',
      '`Target ` `' + url.substring(0, 34) + '`',
      '`Status ` ' + (r.vulnerable ? '*VULNERABLE*' : 'SAFE'),
      '`Tests  ` ' + r.tests.length + ' vectors',
      '',
      r.vulnerable ? '`!` _Open redirect to external domain_' : '_No open redirect detected._',
    ].join('\n');
  }

  return reportText;
}

// ── Message handler ───────────────────────────────────────────────────────────

async function handleMessage(message) {
  const chatId = message.chat.id;
  const text = message.text || '';

  if (text === '/start') {
    clearSession(chatId);
    return sendMsg(chatId, msg.welcomeMessage(message.from.first_name), { reply_markup: mainMenu().reply_markup });
  }
  if (text === '/help') {
    return sendMsg(chatId, msg.helpMessage(), { reply_markup: backOnly().reply_markup });
  }
  if (text === '/cancel') {
    clearSession(chatId);
    return sendMsg(chatId, '_Cancelled._', { reply_markup: mainMenu().reply_markup });
  }

  // /scan <url>
  const scanCmd = text.match(/^\/scan\s+(.+)/);
  if (scanCmd) {
    const target = scanCmd[1].trim();
    if (!isValidUrl(target)) {
      return sendMsg(chatId, '_Invalid URL. Example:_ `/scan https://example.com`');
    }
    const url = normalizeUrl(target);
    const sent = await sendMsg(chatId, msg.scanningMessage(url));
    const msgId = sent.result && sent.result.message_id;
    if (!msgId) return;
    try {
      const result = await runFastFullScan(chatId, msgId, url);
      return editMsg(chatId, msgId, msg.formatFullReport(result), { reply_markup: backToMain().reply_markup });
    } catch (err) {
      return editMsg(chatId, msgId, '_Scan error: ' + err.message.substring(0, 50) + '_', { reply_markup: mainMenu().reply_markup });
    }
  }

  // URL input from prompt
  if (!text.startsWith('/')) {
    const session = getSession(chatId);
    if (session.state !== 'awaiting_url') return;

    const input = text.trim();
    if (!isValidUrl(input)) {
      return sendMsg(chatId, '_Invalid URL. Try:_ `https://example.com`\n_/cancel to abort_');
    }
    const url = normalizeUrl(input);
    const scanType = session.scanType;
    clearSession(chatId);

    const sent = await sendMsg(chatId, msg.scanningMessage(url));
    const msgId = sent.result && sent.result.message_id;
    if (!msgId) return;

    try {
      let reportText;
      if (scanType === 'full') {
        const result = await runFastFullScan(chatId, msgId, url);
        reportText = msg.formatFullReport(result);
      } else {
        reportText = await runModuleScan(chatId, msgId, url, scanType);
      }
      return editMsg(chatId, msgId, reportText, { reply_markup: backToMain().reply_markup });
    } catch (err) {
      return editMsg(chatId, msgId, '_Scan error: ' + err.message.substring(0, 50) + '_', { reply_markup: mainMenu().reply_markup });
    }
  }
}

// ── Callback handler ──────────────────────────────────────────────────────────

async function handleCallback(query) {
  const chatId = query.message.chat.id;
  const msgId  = query.message.message_id;
  const data   = query.data;

  await answerCB(query.id);
  const edit = (text, extra = {}) => editMsg(chatId, msgId, text, extra);

  if (data === 'menu_main') {
    clearSession(chatId);
    return edit(msg.mainMenuMessage(), { reply_markup: mainMenu().reply_markup });
  }
  if (data === 'menu_scan') {
    clearSession(chatId);
    return edit('*Select Scan Module*\n\nChoose a module to run:', { reply_markup: scanMenu().reply_markup });
  }
  if (data === 'menu_quick') {
    setSession(chatId, { state: 'awaiting_url', scanType: 'quick' });
    return edit(msg.scanPromptMessage('quick'), { reply_markup: backOnly().reply_markup });
  }
  if (data === 'menu_help')     return edit(msg.helpMessage(),     { reply_markup: backOnly().reply_markup });
  if (data === 'menu_about')    return edit(msg.aboutMessage(),    { reply_markup: backOnly().reply_markup });
  if (data === 'menu_settings') return edit(msg.settingsMessage(), { reply_markup: backOnly().reply_markup });
  if (data === 'menu_modules') {
    return edit('*Scanner Modules*\n\nSelect a module to learn more:', { reply_markup: modulesMenu().reply_markup });
  }
  if (data === 'menu_reports') {
    return edit('*Reports*\n\n_No saved report in this session._\nUse `/scan <url>` or Full Scan.', { reply_markup: backOnly().reply_markup });
  }

  if (data.startsWith('info_')) {
    return edit(msg.moduleInfoMessage(data.replace('info_', '')), { reply_markup: backOnly().reply_markup });
  }

  const SCAN_TYPES = ['full', 'headers', 'ssl', 'sqli', 'xss', 'cors', 'redirect'];
  const match = SCAN_TYPES.find(t => data === `scan_${t}`);
  if (match) {
    setSession(chatId, { state: 'awaiting_url', scanType: match });
    return edit(msg.scanPromptMessage(match), { reply_markup: backOnly().reply_markup });
  }
}

// ── Vercel handler ────────────────────────────────────────────────────────────

module.exports = async (req, res) => {
  if (req.method === 'GET') {
    return res.status(200).json({ status: 'IwxBot running', version: '3.0', bot: '@IWXToolsBot' });
  }
  if (req.method !== 'POST') return res.status(405).end();

  if (WEBHOOK_SECRET) {
    const token = req.headers['x-telegram-bot-api-secret-token'] || '';
    if (token !== WEBHOOK_SECRET) return res.status(403).end();
  }

  // Respond immediately — Telegram requires <5s
  res.status(200).json({ ok: true });

  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    if (!body) return;
    if (body.message)        await handleMessage(body.message);
    if (body.callback_query) await handleCallback(body.callback_query);
  } catch (err) {
    console.error('[ERR]', err.message);
  }
};
