// Vercel Serverless Webhook Handler — uses native https (no heavy dependencies)
const https = require('https');
const crypto = require('crypto');

const TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || '';

// ── Telegram API helper ──────────────────────────────────────────────────────
function tgCall(method, body) {
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
      res.on('end', () => { try { resolve(JSON.parse(raw)); } catch { resolve(raw); } });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

const sendMessage = (chat_id, text, extra = {}) =>
  tgCall('sendMessage', { chat_id, text, parse_mode: 'Markdown', ...extra });

const editMessageText = (chat_id, message_id, text, extra = {}) =>
  tgCall('editMessageText', { chat_id, message_id, text, parse_mode: 'Markdown', ...extra });

const answerCallbackQuery = (callback_query_id) =>
  tgCall('answerCallbackQuery', { callback_query_id });

// ── Scanner ──────────────────────────────────────────────────────────────────
const scanner = require('../lib/scanner');
const { mainMenu, scanMenu, modulesMenu, backToMain } = require('../lib/keyboards');
const {
  welcomeMessage, mainMenuMessage, helpMessage, aboutMessage,
  scanPromptMessage, scanningMessage, formatFullReport,
  formatHeadersReport, formatSslReport, formatQuickReport, moduleInfoMessage,
} = require('../lib/messages');

// ── In-memory sessions (stateless per cold start — acceptable for webhook) ──
const sessions = {};
function getSession(id) { if (!sessions[id]) sessions[id] = { state: 'idle', scanType: null }; return sessions[id]; }
function setSession(id, d) { sessions[id] = { ...getSession(id), ...d }; }
function clearSession(id) { sessions[id] = { state: 'idle', scanType: null }; }

function isValidUrl(str) {
  try {
    const u = str.startsWith('http') ? str : 'https://' + str;
    new URL(u); return true;
  } catch { return false; }
}
function normalizeUrl(str) { return str.startsWith('http') ? str : 'https://' + str; }

// ── Message handler ──────────────────────────────────────────────────────────
async function handleMessage(msg) {
  const chatId = msg.chat.id;
  const text = msg.text || '';

  if (text === '/start') {
    clearSession(chatId);
    return sendMessage(chatId, welcomeMessage(msg.from.first_name), mainMenu().reply_markup && { reply_markup: mainMenu().reply_markup });
  }
  if (text === '/help') {
    return sendMessage(chatId, helpMessage(), { reply_markup: backToMain().reply_markup });
  }
  if (text === '/cancel') {
    clearSession(chatId);
    return sendMessage(chatId, '`  Operation cancelled.                 `', { reply_markup: mainMenu().reply_markup });
  }

  const scanCmd = text.match(/^\/scan (.+)/);
  if (scanCmd) {
    const target = scanCmd[1].trim();
    if (!isValidUrl(target)) {
      return sendMessage(chatId, '`  [ERROR] Invalid URL format.`');
    }
    const url = normalizeUrl(target);
    const sent = await sendMessage(chatId, scanningMessage(url));
    try {
      const result = await scanner.fullScan(url);
      return editMessageText(chatId, sent.result.message_id, formatFullReport(result), { reply_markup: backToMain().reply_markup });
    } catch (err) {
      return editMessageText(chatId, sent.result.message_id, `\`  [ERROR] ${err.message.substring(0, 50)}\``, { reply_markup: mainMenu().reply_markup });
    }
  }

  if (!text.startsWith('/')) {
    const session = getSession(chatId);
    if (session.state === 'awaiting_url') {
      if (!isValidUrl(text.trim())) {
        return sendMessage(chatId, '`  [ERROR] Invalid URL. Try: https://example.com`\n_Or /cancel to abort._');
      }
      const url = normalizeUrl(text.trim());
      const scanType = session.scanType;
      clearSession(chatId);
      const sent = await sendMessage(chatId, scanningMessage(url));
      const msgId = sent.result.message_id;

      try {
        let reportText;
        if (scanType === 'full') {
          reportText = formatFullReport(await scanner.fullScan(url));
        } else if (scanType === 'quick') {
          const [h, s] = await Promise.all([scanner.checkHttpHeaders(url), scanner.checkSsl(url)]);
          reportText = formatQuickReport(h, s);
        } else if (scanType === 'headers') {
          const r = await scanner.checkHttpHeaders(url); r.url = url;
          reportText = formatHeadersReport(r);
        } else if (scanType === 'ssl') {
          reportText = formatSslReport(await scanner.checkSsl(url), url);
        } else if (scanType === 'sqli') {
          const r = await scanner.checkSqlInjection(url);
          const status = r.vulnerable ? '[VULNERABLE]' : '[SAFE]';
          reportText = `\`────────────────────────────────────────\`\n\`  SQL INJECTION REPORT                 \`\n\`────────────────────────────────────────\`\n\n*Target:* \`${url.substring(0,45)}\`\n*Status:* \`${status}\`\n*Tests:*  \`${r.tests.length} payloads sent\`\n\n${r.vulnerable ? r.details.map(d=>`\`  ! ${d.substring(0,33)}\``).join('\n') : '`  No SQL error patterns detected.     `'}`;
        } else if (scanType === 'xss') {
          const r = await scanner.checkXss(url);
          const status = r.vulnerable ? '[VULNERABLE]' : '[SAFE]';
          reportText = `\`────────────────────────────────────────\`\n\`  XSS SCAN REPORT                     \`\n\`────────────────────────────────────────\`\n\n*Target:* \`${url.substring(0,45)}\`\n*Status:* \`${status}\`\n*Tests:*  \`${r.tests.length} payloads sent\`\n\n${r.vulnerable ? r.details.map(d=>`\`  ! ${d.substring(0,33)}\``).join('\n') : '`  No reflected XSS detected.          `'}`;
        } else if (scanType === 'cors') {
          const r = await scanner.checkCors(url);
          reportText = `\`────────────────────────────────────────\`\n\`  CORS AUDIT REPORT                   \`\n\`────────────────────────────────────────\`\n\n*Target:* \`${url.substring(0,45)}\`\n*Status:* \`${r.misconfigured ? '[MISCONFIGURED]' : '[SAFE]'}\`\n\`  Allow-Origin: ${String(r.allowOrigin||'Not set').substring(0,22).padEnd(22)}\`\n\n${r.details.map(d=>`\`  ${d.substring(0,37)}\``).join('\n')}`;
        } else if (scanType === 'redirect') {
          const r = await scanner.checkOpenRedirect(url);
          reportText = `\`────────────────────────────────────────\`\n\`  OPEN REDIRECT REPORT                \`\n\`────────────────────────────────────────\`\n\n*Target:* \`${url.substring(0,45)}\`\n*Status:* \`${r.vulnerable ? '[VULNERABLE]' : '[SAFE]'}\`\n*Tests:*  \`${r.tests.length} vectors tested\`\n\n${r.vulnerable ? '`  ! Open redirect to external domain  `' : '`  No open redirect detected.         `'}`;
        }
        return editMessageText(chatId, msgId, reportText, { reply_markup: backToMain().reply_markup });
      } catch (err) {
        return editMessageText(chatId, msgId, `\`  [ERROR] Scan failed: ${err.message.substring(0,40)}\``, { reply_markup: mainMenu().reply_markup });
      }
    }
  }
}

// ── Callback handler ─────────────────────────────────────────────────────────
async function handleCallback(query) {
  const chatId = query.message.chat.id;
  const msgId = query.message.message_id;
  const data = query.data;

  await answerCallbackQuery(query.id);

  const edit = (text, extra = {}) =>
    editMessageText(chatId, msgId, text, extra);

  if (data === 'menu_main') {
    clearSession(chatId);
    return edit(mainMenuMessage(), { reply_markup: mainMenu().reply_markup });
  }
  if (data === 'menu_scan' || data === 'menu_full') {
    clearSession(chatId);
    return edit(
      '`────────────────────────────────────────`\n`  SELECT SCAN MODULE                   `\n`────────────────────────────────────────`',
      { reply_markup: scanMenu().reply_markup }
    );
  }
  if (data === 'menu_quick') {
    setSession(chatId, { state: 'awaiting_url', scanType: 'quick' });
    return edit(scanPromptMessage('quick'), { reply_markup: backToMain().reply_markup });
  }
  if (data === 'menu_help') return edit(helpMessage(), { reply_markup: backToMain().reply_markup });
  if (data === 'menu_about') return edit(aboutMessage(), { reply_markup: backToMain().reply_markup });
  if (data === 'menu_modules') {
    return edit(
      '`────────────────────────────────────────`\n`  SCANNER MODULES                      `\n`────────────────────────────────────────`\n\nSelect a module to view its details:',
      { reply_markup: modulesMenu().reply_markup }
    );
  }
  if (data === 'menu_reports') {
    return edit(
      '`────────────────────────────────────────`\n`  REPORTS                              `\n`────────────────────────────────────────`\n\n_Reports are stored per session._\n_Use /scan \\<url\\> to generate a new report._',
      { reply_markup: backToMain().reply_markup }
    );
  }
  if (data === 'menu_settings') {
    return edit(
      '`────────────────────────────────────────`\n`  SETTINGS                             `\n`────────────────────────────────────────`\n\n`  Timeout:       10 seconds            `\n`  Max Redirects: 5                     `\n`  User-Agent:    VulnScan-Bot/1.0      `\n`  Mode:          Passive + Active      `',
      { reply_markup: backToMain().reply_markup }
    );
  }
  if (data.startsWith('info_')) {
    return edit(moduleInfoMessage(data.replace('info_', '')), { reply_markup: backToMain().reply_markup });
  }

  const scanTypes = ['full', 'headers', 'ssl', 'sqli', 'xss', 'cors', 'redirect'];
  const scanMatch = scanTypes.find(t => data === `scan_${t}`);
  if (scanMatch) {
    setSession(chatId, { state: 'awaiting_url', scanType: scanMatch });
    return edit(scanPromptMessage(scanMatch), { reply_markup: backToMain().reply_markup });
  }
}

// ── Vercel handler ───────────────────────────────────────────────────────────
module.exports = async (req, res) => {
  if (req.method === 'GET') {
    return res.status(200).json({ status: 'IwxBot is running.', bot: '@IWXToolsBot' });
  }
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Validate Telegram secret token if configured
  if (WEBHOOK_SECRET) {
    const incoming = req.headers['x-telegram-bot-api-secret-token'] || '';
    if (incoming !== WEBHOOK_SECRET) {
      return res.status(403).json({ error: 'Forbidden' });
    }
  }

  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    if (!body) return res.status(200).json({ ok: true });
    if (body.message) await handleMessage(body.message);
    if (body.callback_query) await handleCallback(body.callback_query);
    res.status(200).json({ ok: true });
  } catch (err) {
    console.error('[WEBHOOK ERROR]', err.message, err.stack);
    res.status(200).json({ ok: false, error: err.message });
  }
};
