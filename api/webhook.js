// Vercel Serverless Function - Telegram Webhook Handler
const crypto = require('crypto');
const TelegramBot = require('node-telegram-bot-api');
const { fullScan, checkHttpHeaders, checkSsl, checkSqlInjection, checkXss, checkCors, checkOpenRedirect, normalizeUrl } = require('../lib/scanner');
const { mainMenu, scanMenu, modulesMenu, backToMain } = require('../lib/keyboards');
const {
  welcomeMessage, mainMenuMessage, helpMessage, aboutMessage,
  scanPromptMessage, scanningMessage, formatFullReport,
  formatHeadersReport, formatSslReport, formatQuickReport, moduleInfoMessage,
} = require('../lib/messages');

const TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || '';
const bot = new TelegramBot(TOKEN);

// In-memory store (stateless per request — use Redis/DB for production)
const sessions = {};

function getSession(chatId) {
  if (!sessions[chatId]) sessions[chatId] = { state: 'idle', scanType: null };
  return sessions[chatId];
}

function setSession(chatId, data) {
  sessions[chatId] = { ...getSession(chatId), ...data };
}

function clearSession(chatId) {
  sessions[chatId] = { state: 'idle', scanType: null };
}

function isValidUrl(str) {
  try { new URL(normalizeUrl(str)); return true; } catch { return false; }
}

async function handleMessage(msg) {
  const chatId = msg.chat.id;

  if (msg.text === '/start') {
    clearSession(chatId);
    await bot.sendMessage(chatId, welcomeMessage(msg.from.first_name), {
      parse_mode: 'Markdown', ...mainMenu(),
    });
    return;
  }

  if (msg.text === '/help') {
    await bot.sendMessage(chatId, helpMessage(), {
      parse_mode: 'Markdown', ...backToMain(),
    });
    return;
  }

  if (msg.text === '/cancel') {
    clearSession(chatId);
    await bot.sendMessage(chatId, '`  Operation cancelled.                 `', {
      parse_mode: 'Markdown', ...mainMenu(),
    });
    return;
  }

  const scanMatch = msg.text && msg.text.match(/^\/scan (.+)/);
  if (scanMatch) {
    const target = scanMatch[1].trim();
    if (!isValidUrl(target)) {
      await bot.sendMessage(chatId, '`  [ERROR] Invalid URL.`', { parse_mode: 'Markdown' });
      return;
    }
    const url = normalizeUrl(target);
    const sent = await bot.sendMessage(chatId, scanningMessage(url), { parse_mode: 'Markdown' });
    try {
      const result = await fullScan(url);
      await bot.editMessageText(formatFullReport(result), {
        chat_id: chatId, message_id: sent.message_id,
        parse_mode: 'Markdown', reply_markup: backToMain().reply_markup,
      });
    } catch (err) {
      await bot.editMessageText(`\`  [ERROR] ${err.message.substring(0, 50)}\``, {
        chat_id: chatId, message_id: sent.message_id,
        parse_mode: 'Markdown', reply_markup: mainMenu().reply_markup,
      });
    }
    return;
  }

  if (msg.text && !msg.text.startsWith('/')) {
    const session = getSession(chatId);
    if (session.state === 'awaiting_url') {
      const input = msg.text.trim();
      if (!isValidUrl(input)) {
        await bot.sendMessage(chatId, '`  [ERROR] Invalid URL format.`\n_Send a valid URL like https://example.com_\n_Or /cancel to abort._', {
          parse_mode: 'Markdown',
        });
        return;
      }
      const url = normalizeUrl(input);
      const scanType = session.scanType;
      clearSession(chatId);
      const sent = await bot.sendMessage(chatId, scanningMessage(url), { parse_mode: 'Markdown' });

      try {
        let reportText;
        if (scanType === 'full') {
          const result = await fullScan(url);
          reportText = formatFullReport(result);
        } else if (scanType === 'headers') {
          const result = await checkHttpHeaders(url);
          result.url = url;
          reportText = formatHeadersReport(result);
        } else if (scanType === 'ssl') {
          const result = await checkSsl(url);
          reportText = formatSslReport(result, url);
        } else if (scanType === 'quick') {
          const [h, s] = await Promise.all([checkHttpHeaders(url), checkSsl(url)]);
          reportText = formatQuickReport(h, s);
        } else if (scanType === 'sqli') {
          const r = await checkSqlInjection(url);
          reportText = `\`────────────────────────────────────────\`\n\`  SQL INJECTION REPORT                 \`\n\`────────────────────────────────────────\`\n\n*Target:* \`${url}\`\n*Status:* \`${r.vulnerable ? '[VULNERABLE]' : '[SAFE]'}\`\n\n${r.vulnerable ? r.details.map(d => `\`  ! ${d.substring(0, 33)}\``).join('\n') : '`  No SQL error patterns detected.     `'}`;
        } else if (scanType === 'xss') {
          const r = await checkXss(url);
          reportText = `\`────────────────────────────────────────\`\n\`  XSS SCAN REPORT                     \`\n\`────────────────────────────────────────\`\n\n*Target:* \`${url}\`\n*Status:* \`${r.vulnerable ? '[VULNERABLE]' : '[SAFE]'}\`\n\n${r.vulnerable ? r.details.map(d => `\`  ! ${d.substring(0, 33)}\``).join('\n') : '`  No reflected XSS detected.          `'}`;
        } else if (scanType === 'cors') {
          const r = await checkCors(url);
          reportText = `\`────────────────────────────────────────\`\n\`  CORS AUDIT REPORT                   \`\n\`────────────────────────────────────────\`\n\n*Target:* \`${url}\`\n*Status:* \`${r.misconfigured ? '[MISCONFIGURED]' : '[SAFE]'}\`\n\`  Allow-Origin: ${String(r.allowOrigin || 'Not set').substring(0, 22).padEnd(22)}\`\n\n${r.details.map(d => `\`  ${d.substring(0, 37)}\``).join('\n')}`;
        } else if (scanType === 'redirect') {
          const r = await checkOpenRedirect(url);
          reportText = `\`────────────────────────────────────────\`\n\`  OPEN REDIRECT REPORT                \`\n\`────────────────────────────────────────\`\n\n*Target:* \`${url}\`\n*Status:* \`${r.vulnerable ? '[VULNERABLE]' : '[SAFE]'}\`\n\n${r.vulnerable ? '`  ! Open redirect to external domain  `' : '`  No open redirect detected.         `'}`;
        }

        await bot.editMessageText(reportText, {
          chat_id: chatId, message_id: sent.message_id,
          parse_mode: 'Markdown', reply_markup: backToMain().reply_markup,
        });
      } catch (err) {
        await bot.editMessageText(`\`  [ERROR] Scan failed: ${err.message.substring(0, 40)}\``, {
          chat_id: chatId, message_id: sent.message_id,
          parse_mode: 'Markdown', reply_markup: mainMenu().reply_markup,
        });
      }
    }
  }
}

async function handleCallbackQuery(query) {
  const chatId = query.message.chat.id;
  const msgId = query.message.message_id;
  const data = query.data;

  await bot.answerCallbackQuery(query.id);

  if (data === 'menu_main') {
    clearSession(chatId);
    await bot.editMessageText(mainMenuMessage(), { chat_id: chatId, message_id: msgId, parse_mode: 'Markdown', ...mainMenu() });
    return;
  }
  if (data === 'menu_scan' || data === 'menu_full') {
    clearSession(chatId);
    await bot.editMessageText('`────────────────────────────────────────`\n`  SELECT SCAN MODULE                   `\n`────────────────────────────────────────`', {
      chat_id: chatId, message_id: msgId, parse_mode: 'Markdown', ...scanMenu(),
    });
    return;
  }
  if (data === 'menu_quick') {
    setSession(chatId, { state: 'awaiting_url', scanType: 'quick' });
    await bot.editMessageText(scanPromptMessage('quick'), { chat_id: chatId, message_id: msgId, parse_mode: 'Markdown', ...backToMain() });
    return;
  }
  if (data === 'menu_help') {
    await bot.editMessageText(helpMessage(), { chat_id: chatId, message_id: msgId, parse_mode: 'Markdown', ...backToMain() });
    return;
  }
  if (data === 'menu_about') {
    await bot.editMessageText(aboutMessage(), { chat_id: chatId, message_id: msgId, parse_mode: 'Markdown', ...backToMain() });
    return;
  }
  if (data === 'menu_modules') {
    await bot.editMessageText('`────────────────────────────────────────`\n`  SCANNER MODULES                      `\n`────────────────────────────────────────`\n\nSelect a module to view its details:', {
      chat_id: chatId, message_id: msgId, parse_mode: 'Markdown', ...modulesMenu(),
    });
    return;
  }
  if (data === 'menu_reports') {
    await bot.editMessageText('`────────────────────────────────────────`\n`  REPORTS                              `\n`────────────────────────────────────────`\n\n_Reports are stored per session._\n_Use /scan <url> to generate a new report._', {
      chat_id: chatId, message_id: msgId, parse_mode: 'Markdown', ...backToMain(),
    });
    return;
  }
  if (data === 'menu_settings') {
    await bot.editMessageText('`────────────────────────────────────────`\n`  SETTINGS                             `\n`────────────────────────────────────────`\n\n`  Timeout:       10 seconds            `\n`  Max Redirects: 5                     `\n`  User-Agent:    VulnScan-Bot/1.0      `\n`  Mode:          Passive + Active      `', {
      chat_id: chatId, message_id: msgId, parse_mode: 'Markdown', ...backToMain(),
    });
    return;
  }
  if (data.startsWith('info_')) {
    const module = data.replace('info_', '');
    await bot.editMessageText(moduleInfoMessage(module), { chat_id: chatId, message_id: msgId, parse_mode: 'Markdown', ...backToMain() });
    return;
  }

  const scanTypes = ['full', 'headers', 'ssl', 'sqli', 'xss', 'cors', 'redirect'];
  const scanMatch = scanTypes.find(t => data === `scan_${t}`);
  if (scanMatch) {
    setSession(chatId, { state: 'awaiting_url', scanType: scanMatch });
    await bot.editMessageText(scanPromptMessage(scanMatch), { chat_id: chatId, message_id: msgId, parse_mode: 'Markdown', ...backToMain() });
    return;
  }
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(200).json({ status: 'VulnScan Bot is running.' });
  }

  // Validate Telegram secret token header (set when registering webhook)
  if (WEBHOOK_SECRET) {
    const incoming = req.headers['x-telegram-bot-api-secret-token'] || '';
    const expected = crypto
      .createHmac('sha256', 'WebHook')
      .update(WEBHOOK_SECRET)
      .digest('hex');
    if (!crypto.timingSafeEqual(Buffer.from(incoming), Buffer.from(expected))) {
      return res.status(403).json({ error: 'Forbidden' });
    }
  }

  try {
    const body = req.body;
    if (body.message) await handleMessage(body.message);
    if (body.callback_query) await handleCallbackQuery(body.callback_query);
    res.status(200).json({ ok: true });
  } catch (err) {
    console.error('[WEBHOOK ERROR]', err.message);
    res.status(200).json({ ok: false, error: err.message });
  }
};
