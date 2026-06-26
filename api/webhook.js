// IwxBot — Vercel Serverless Webhook Handler v2
// Animated scan progress via sequential message edits
const https = require('https');
const crypto = require('crypto');

const TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || '';

// ── Telegram API ─────────────────────────────────────────────────────────────

function tg(method, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = https.request({
      hostname: 'api.telegram.org',
      path: `/bot${TOKEN}/${method}`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
      },
    }, (res) => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => { try { resolve(JSON.parse(raw)); } catch { resolve({}); } });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

const sendMsg  = (chat_id, text, extra = {}) =>
  tg('sendMessage', { chat_id, text, parse_mode: 'Markdown', ...extra });

const editMsg  = (chat_id, message_id, text, extra = {}) =>
  tg('editMessageText', { chat_id, message_id, text, parse_mode: 'Markdown', ...extra });

const answerCB = (callback_query_id, text) =>
  tg('answerCallbackQuery', { callback_query_id, ...(text ? { text } : {}) });

// ── Modules ───────────────────────────────────────────────────────────────────

const scanner = require('../lib/scanner');
const { mainMenu, scanMenu, modulesMenu, backToMain, backOnly } = require('../lib/keyboards');
const msg = require('../lib/messages');

// ── Session store (in-memory per cold start) ──────────────────────────────────

const sessions = {};
const getSession  = id => sessions[id] || (sessions[id] = { state: 'idle', scanType: null });
const setSession  = (id, d) => { sessions[id] = { ...getSession(id), ...d }; };
const clearSession = id => { sessions[id] = { state: 'idle', scanType: null }; };

// ── URL helpers ───────────────────────────────────────────────────────────────

const normalizeUrl = s => s.startsWith('http') ? s : 'https://' + s;
function isValidUrl(s) {
  try { new URL(normalizeUrl(s)); return true; } catch { return false; }
}

// ── Animated scanner ──────────────────────────────────────────────────────────
// Runs modules sequentially, editing the progress message after each step.

async function runAnimatedFullScan(chatId, msgId, url) {
  const update = (stepIndex) =>
    editMsg(chatId, msgId, msg.scanProgressMessage(url, stepIndex));

  await update(0); // Initializing

  // Run each module and update progress after each
  await update(1);
  const ssl = await scanner.checkSsl(url).catch(() => ({ enabled: false, grade: 'F', issues: ['Scan error'] }));

  await update(2);
  const headers = await scanner.checkHttpHeaders(url).catch(() => ({ url, score: 0, server: 'N/A', presentHeaders: [], missingHeaders: [], statusCode: 0 }));
  headers.url = url;

  await update(3);
  const sqli = await scanner.checkSqlInjection(url).catch(() => ({ vulnerable: false, tests: [], details: [] }));

  await update(4);
  const xss = await scanner.checkXss(url).catch(() => ({ vulnerable: false, tests: [], details: [] }));

  await update(5);
  const cors = await scanner.checkCors(url).catch(() => ({ misconfigured: false, details: [], allowOrigin: 'N/A' }));

  await update(6);
  const redirect = await scanner.checkOpenRedirect(url).catch(() => ({ vulnerable: false, tests: [] }));

  await update(7); // Compiling

  // Calculate risk
  let riskScore = 0;
  let criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0;
  if (sqli.vulnerable)                      { riskScore += 40; criticalCount++; }
  if (xss.vulnerable)                       { riskScore += 30; highCount++; }
  if (cors.misconfigured)                   { riskScore += 25; highCount++; }
  if (redirect.vulnerable)                  { riskScore += 20; mediumCount++; }
  if (ssl.grade === 'F')                    { riskScore += 30; highCount++; }
  if (headers.missingHeaders.length > 5)   { riskScore += 15; mediumCount++; }
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
    headers,
    ssl,
    sqli,
    xss,
    cors,
    redirect,
  };
}

// ── Single-module scan with animation ────────────────────────────────────────

async function runModuleScan(chatId, msgId, url, scanType) {
  const stepMap = {
    ssl: 1, headers: 2, sqli: 3, xss: 4, cors: 5, redirect: 6, quick: 2,
  };
  const updateStep = stepMap[scanType] || 1;

  // Show progress start
  await editMsg(chatId, msgId, msg.scanProgressMessage(url, 0));
  await new Promise(r => setTimeout(r, 400));
  await editMsg(chatId, msgId, msg.scanProgressMessage(url, updateStep));

  let reportText;

  if (scanType === 'quick') {
    const [h, s] = await Promise.all([
      scanner.checkHttpHeaders(url).catch(() => ({ url, score: 0, presentHeaders: [], missingHeaders: [] })),
      scanner.checkSsl(url).catch(() => ({ enabled: false, grade: 'F', issues: [] })),
    ]);
    h.url = url;
    await editMsg(chatId, msgId, msg.scanProgressMessage(url, 7));
    reportText = msg.formatQuickReport(h, s);

  } else if (scanType === 'headers') {
    const r = await scanner.checkHttpHeaders(url);
    r.url = url;
    await editMsg(chatId, msgId, msg.scanProgressMessage(url, 7));
    reportText = msg.formatHeadersReport(r);

  } else if (scanType === 'ssl') {
    const r = await scanner.checkSsl(url);
    await editMsg(chatId, msgId, msg.scanProgressMessage(url, 7));
    reportText = msg.formatSslReport(r, url);

  } else if (scanType === 'sqli') {
    const r = await scanner.checkSqlInjection(url);
    await editMsg(chatId, msgId, msg.scanProgressMessage(url, 7));
    const status = r.vulnerable ? 'VULNERABLE' : 'SAFE';
    reportText = [
      msg.header('SQL Injection Report'),
      '',
      msg.kv('Target', url.substring(0, 28)),
      msg.kv('Status', status),
      msg.kv('Tests Run', r.tests.length + ' payloads'),
      '',
      msg.rule(msg.THIN),
      ...(r.vulnerable
        ? [msg.box(' Findings:'), ...r.details.map(d => msg.box('  ! ' + d.substring(0, 32)))]
        : [msg.box(' No SQL error patterns detected.')]),
      '',
      msg.rule(msg.THICK),
    ].join('\n');

  } else if (scanType === 'xss') {
    const r = await scanner.checkXss(url);
    await editMsg(chatId, msgId, msg.scanProgressMessage(url, 7));
    const status = r.vulnerable ? 'VULNERABLE' : 'SAFE';
    reportText = [
      msg.header('XSS Scan Report'),
      '',
      msg.kv('Target', url.substring(0, 28)),
      msg.kv('Status', status),
      msg.kv('Tests Run', r.tests.length + ' payloads'),
      '',
      msg.rule(msg.THIN),
      ...(r.vulnerable
        ? [msg.box(' Findings:'), ...r.details.map(d => msg.box('  ! ' + d.substring(0, 32)))]
        : [msg.box(' No reflected XSS detected.')]),
      '',
      msg.rule(msg.THICK),
    ].join('\n');

  } else if (scanType === 'cors') {
    const r = await scanner.checkCors(url);
    await editMsg(chatId, msgId, msg.scanProgressMessage(url, 7));
    reportText = [
      msg.header('CORS Audit Report'),
      '',
      msg.kv('Target', url.substring(0, 28)),
      msg.kv('Status', r.misconfigured ? 'MISCONFIGURED' : 'SAFE'),
      msg.kv('Allow-Origin', String(r.allowOrigin || 'Not set').substring(0, 18)),
      '',
      msg.rule(msg.THIN),
      ...r.details.map(d => msg.box('  ' + d.substring(0, 34))),
      '',
      msg.rule(msg.THICK),
    ].join('\n');

  } else if (scanType === 'redirect') {
    const r = await scanner.checkOpenRedirect(url);
    await editMsg(chatId, msgId, msg.scanProgressMessage(url, 7));
    reportText = [
      msg.header('Open Redirect Report'),
      '',
      msg.kv('Target', url.substring(0, 28)),
      msg.kv('Status', r.vulnerable ? 'VULNERABLE' : 'SAFE'),
      msg.kv('Tests Run', r.tests.length + ' vectors'),
      '',
      msg.rule(msg.THIN),
      r.vulnerable
        ? msg.box('  ! Open redirect to external domain')
        : msg.box('  No open redirect detected.'),
      '',
      msg.rule(msg.THICK),
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
    return sendMsg(chatId, msg.box(' Operation cancelled.'), { reply_markup: mainMenu().reply_markup });
  }

  // /scan <url>
  const scanCmd = text.match(/^\/scan\s+(.+)/);
  if (scanCmd) {
    const target = scanCmd[1].trim();
    if (!isValidUrl(target)) {
      return sendMsg(chatId, msg.box(' [ERROR] Invalid URL format.') + '\n_Example: /scan https://example.com_');
    }
    const url = normalizeUrl(target);
    const sent = await sendMsg(chatId, msg.scanningMessage(url));
    const msgId = sent.result && sent.result.message_id;
    if (!msgId) return;
    try {
      const result = await runAnimatedFullScan(chatId, msgId, url);
      return editMsg(chatId, msgId, msg.formatFullReport(result), { reply_markup: backToMain().reply_markup });
    } catch (err) {
      return editMsg(chatId, msgId, msg.box(' [ERROR] ' + err.message.substring(0, 35)), { reply_markup: mainMenu().reply_markup });
    }
  }

  // URL input from scan prompt
  if (!text.startsWith('/')) {
    const session = getSession(chatId);
    if (session.state !== 'awaiting_url') return;

    const input = text.trim();
    if (!isValidUrl(input)) {
      return sendMsg(chatId, msg.box(' [ERROR] Invalid URL.') + '\n_Send: https://example.com_\n_Or /cancel_');
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
        const result = await runAnimatedFullScan(chatId, msgId, url);
        reportText = msg.formatFullReport(result);
      } else {
        reportText = await runModuleScan(chatId, msgId, url, scanType);
      }
      return editMsg(chatId, msgId, reportText, { reply_markup: backToMain().reply_markup });
    } catch (err) {
      return editMsg(chatId, msgId, msg.box(' [ERROR] ' + err.message.substring(0, 35)), { reply_markup: mainMenu().reply_markup });
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

  // Navigation
  if (data === 'menu_main') {
    clearSession(chatId);
    return edit(msg.mainMenuMessage(), { reply_markup: mainMenu().reply_markup });
  }
  if (data === 'menu_scan') {
    clearSession(chatId);
    return edit(
      msg.header('Select Module') + '\n\n' + msg.box(' Choose a scan module below:'),
      { reply_markup: scanMenu().reply_markup }
    );
  }
  if (data === 'menu_quick') {
    setSession(chatId, { state: 'awaiting_url', scanType: 'quick' });
    return edit(msg.scanPromptMessage('quick'), { reply_markup: backOnly().reply_markup });
  }
  if (data === 'menu_help') {
    return edit(msg.helpMessage(), { reply_markup: backOnly().reply_markup });
  }
  if (data === 'menu_about') {
    return edit(msg.aboutMessage(), { reply_markup: backOnly().reply_markup });
  }
  if (data === 'menu_settings') {
    return edit(msg.settingsMessage(), { reply_markup: backOnly().reply_markup });
  }
  if (data === 'menu_modules') {
    return edit(
      msg.header('Scanner Modules') + '\n\n' + msg.box(' Select a module to learn more:'),
      { reply_markup: modulesMenu().reply_markup }
    );
  }
  if (data === 'menu_reports') {
    return edit(
      msg.header('Reports') + '\n\n' +
      msg.box(' No saved report in this session.') + '\n' +
      msg.box(' Use /scan <url> or Full Scan') + '\n' +
      msg.box(' to generate a new report.'),
      { reply_markup: backOnly().reply_markup }
    );
  }

  // Module info
  if (data.startsWith('info_')) {
    return edit(msg.moduleInfoMessage(data.replace('info_', '')), { reply_markup: backOnly().reply_markup });
  }

  // Scan type selection
  const scanTypes = ['full', 'headers', 'ssl', 'sqli', 'xss', 'cors', 'redirect'];
  const scanMatch = scanTypes.find(t => data === `scan_${t}`);
  if (scanMatch) {
    setSession(chatId, { state: 'awaiting_url', scanType: scanMatch });
    return edit(msg.scanPromptMessage(scanMatch), { reply_markup: backOnly().reply_markup });
  }
}

// ── Vercel export ─────────────────────────────────────────────────────────────

module.exports = async (req, res) => {
  if (req.method === 'GET') {
    return res.status(200).json({ status: 'IwxBot is running.', bot: '@IWXToolsBot', version: '2.0' });
  }
  if (req.method !== 'POST') {
    return res.status(405).end();
  }

  // Validate webhook secret
  if (WEBHOOK_SECRET) {
    const incoming = req.headers['x-telegram-bot-api-secret-token'] || '';
    if (incoming !== WEBHOOK_SECRET) {
      return res.status(403).json({ error: 'Forbidden' });
    }
  }

  // Always respond 200 immediately (Telegram requires <5s)
  res.status(200).json({ ok: true });

  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    if (!body) return;
    if (body.message)        await handleMessage(body.message);
    if (body.callback_query) await handleCallback(body.callback_query);
  } catch (err) {
    console.error('[WEBHOOK ERROR]', err.message, err.stack);
  }
};
