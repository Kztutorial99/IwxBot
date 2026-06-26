require('dotenv').config();
const TelegramBot = require('node-telegram-bot-api');
const { fullScan, checkHttpHeaders, checkSsl, checkSqlInjection, checkXss, checkCors, checkOpenRedirect, normalizeUrl } = require('./lib/scanner');
const { mainMenu, scanMenu, modulesMenu, backToMain } = require('./lib/keyboards');
const {
  welcomeMessage, mainMenuMessage, helpMessage, aboutMessage,
  scanPromptMessage, scanningMessage, formatFullReport,
  formatHeadersReport, formatSslReport, formatQuickReport, moduleInfoMessage,
} = require('./lib/messages');
const { getSession, setSession, clearSession, saveReport, getReport, generateSessionId } = require('./lib/sessions');

const TOKEN = process.env.TELEGRAM_BOT_TOKEN;

if (!TOKEN) {
  console.error('[ERROR] TELEGRAM_BOT_TOKEN is not set.');
  process.exit(1);
}

const bot = new TelegramBot(TOKEN, { polling: true });

console.log('[INFO] VulnScan Bot started in polling mode.');

// ─── Helpers ───────────────────────────────────────────────────────────────

async function sendMain(chatId) {
  await bot.sendMessage(chatId, mainMenuMessage(), {
    parse_mode: 'Markdown',
    ...mainMenu(),
  });
}

async function sendScanMenu(chatId) {
  await bot.sendMessage(chatId, '`────────────────────────────────────────`\n`  SELECT SCAN MODULE                   `\n`────────────────────────────────────────`', {
    parse_mode: 'Markdown',
    ...scanMenu(),
  });
}

function isValidUrl(str) {
  try {
    const url = normalizeUrl(str);
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

// ─── Commands ──────────────────────────────────────────────────────────────

bot.onText(/\/start/, async (msg) => {
  const chatId = msg.chat.id;
  clearSession(chatId);
  await bot.sendMessage(chatId, welcomeMessage(msg.from.first_name), {
    parse_mode: 'Markdown',
    ...mainMenu(),
  });
});

bot.onText(/\/help/, async (msg) => {
  const chatId = msg.chat.id;
  await bot.sendMessage(chatId, helpMessage(), {
    parse_mode: 'Markdown',
    ...backToMain(),
  });
});

bot.onText(/\/cancel/, async (msg) => {
  const chatId = msg.chat.id;
  clearSession(chatId);
  await bot.sendMessage(chatId, '`  Operation cancelled.                 `', {
    parse_mode: 'Markdown',
    ...mainMenu(),
  });
});

bot.onText(/\/scan (.+)/, async (msg, match) => {
  const chatId = msg.chat.id;
  const target = match[1].trim();

  if (!isValidUrl(target)) {
    await bot.sendMessage(chatId, '`  [ERROR] Invalid URL. Include full domain.`\n_Example: /scan example.com_', {
      parse_mode: 'Markdown',
    });
    return;
  }

  const url = normalizeUrl(target);
  const scanning = await bot.sendMessage(chatId, scanningMessage(url), { parse_mode: 'Markdown' });

  try {
    const result = await fullScan(url);
    const sessionId = generateSessionId();
    saveReport(sessionId, result);

    await bot.editMessageText(formatFullReport(result), {
      chat_id: chatId,
      message_id: scanning.message_id,
      parse_mode: 'Markdown',
      reply_markup: backToMain().reply_markup,
    });
  } catch (err) {
    await bot.editMessageText(`\`  [ERROR] Scan failed: ${err.message.substring(0, 40)}\``, {
      chat_id: chatId,
      message_id: scanning.message_id,
      parse_mode: 'Markdown',
      reply_markup: mainMenu().reply_markup,
    });
  }
});

// ─── Callback Query Handler ─────────────────────────────────────────────────

bot.on('callback_query', async (query) => {
  const chatId = query.message.chat.id;
  const msgId = query.message.message_id;
  const data = query.data;

  await bot.answerCallbackQuery(query.id);

  // ── Main navigation ────────────────────────────────────────────────────

  if (data === 'menu_main') {
    clearSession(chatId);
    await bot.editMessageText(mainMenuMessage(), {
      chat_id: chatId, message_id: msgId,
      parse_mode: 'Markdown', ...mainMenu(),
    });
    return;
  }

  if (data === 'menu_scan' || data === 'menu_full') {
    clearSession(chatId);
    await bot.editMessageText(
      '`────────────────────────────────────────`\n`  SELECT SCAN MODULE                   `\n`────────────────────────────────────────`',
      { chat_id: chatId, message_id: msgId, parse_mode: 'Markdown', ...scanMenu() }
    );
    return;
  }

  if (data === 'menu_quick') {
    setSession(chatId, { state: 'awaiting_url', scanType: 'quick' });
    await bot.editMessageText(scanPromptMessage('quick'), {
      chat_id: chatId, message_id: msgId, parse_mode: 'Markdown', ...backToMain(),
    });
    return;
  }

  if (data === 'menu_help') {
    await bot.editMessageText(helpMessage(), {
      chat_id: chatId, message_id: msgId, parse_mode: 'Markdown', ...backToMain(),
    });
    return;
  }

  if (data === 'menu_about') {
    await bot.editMessageText(aboutMessage(), {
      chat_id: chatId, message_id: msgId, parse_mode: 'Markdown', ...backToMain(),
    });
    return;
  }

  if (data === 'menu_modules') {
    await bot.editMessageText(
      '`────────────────────────────────────────`\n`  SCANNER MODULES                      `\n`────────────────────────────────────────`\n\nSelect a module to view its details:',
      { chat_id: chatId, message_id: msgId, parse_mode: 'Markdown', ...modulesMenu() }
    );
    return;
  }

  if (data === 'menu_reports') {
    await bot.editMessageText(
      '`────────────────────────────────────────`\n`  REPORTS                              `\n`────────────────────────────────────────`\n\n_Reports are stored per session._\n_Use /scan <url> to generate a new report._',
      { chat_id: chatId, message_id: msgId, parse_mode: 'Markdown', ...backToMain() }
    );
    return;
  }

  if (data === 'menu_settings') {
    await bot.editMessageText(
      '`────────────────────────────────────────`\n`  SETTINGS                             `\n`────────────────────────────────────────`\n\n`  Timeout:      10 seconds             `\n`  Max Redirects: 5                     `\n`  User-Agent:   VulnScan-Bot/1.0       `\n`  Mode:         Passive + Active       `',
      { chat_id: chatId, message_id: msgId, parse_mode: 'Markdown', ...backToMain() }
    );
    return;
  }

  // ── Module info ────────────────────────────────────────────────────────

  if (data.startsWith('info_')) {
    const module = data.replace('info_', '');
    await bot.editMessageText(moduleInfoMessage(module), {
      chat_id: chatId, message_id: msgId, parse_mode: 'Markdown', ...backToMain(),
    });
    return;
  }

  // ── Scan type selection ────────────────────────────────────────────────

  const scanTypes = ['full', 'headers', 'ssl', 'sqli', 'xss', 'cors', 'redirect'];
  const scanMatch = scanTypes.find(t => data === `scan_${t}`);

  if (scanMatch) {
    setSession(chatId, { state: 'awaiting_url', scanType: scanMatch });
    await bot.editMessageText(scanPromptMessage(scanMatch), {
      chat_id: chatId, message_id: msgId, parse_mode: 'Markdown', ...backToMain(),
    });
    return;
  }
});

// ─── Message Handler (URL input) ───────────────────────────────────────────

bot.on('message', async (msg) => {
  if (msg.text && msg.text.startsWith('/')) return;

  const chatId = msg.chat.id;
  const session = getSession(chatId);

  if (session.state !== 'awaiting_url') return;

  const input = msg.text ? msg.text.trim() : '';

  if (!isValidUrl(input)) {
    await bot.sendMessage(chatId,
      '`  [ERROR] Invalid URL format.          `\n\nSend a valid URL:\n`  https://example.com`\n`  example.com`\n\n_Or /cancel to abort._',
      { parse_mode: 'Markdown' }
    );
    return;
  }

  const url = normalizeUrl(input);
  const scanType = session.scanType;
  clearSession(chatId);

  const scanning = await bot.sendMessage(chatId, scanningMessage(url), { parse_mode: 'Markdown' });

  try {
    let reportText;
    let sessionId;

    if (scanType === 'full' || scanType === 'quick') {
      if (scanType === 'full') {
        const result = await fullScan(url);
        sessionId = generateSessionId();
        saveReport(sessionId, result);
        reportText = formatFullReport(result);
      } else {
        const [headerResult, sslResult] = await Promise.all([
          checkHttpHeaders(url),
          checkSsl(url),
        ]);
        reportText = formatQuickReport(headerResult, sslResult);
      }
    } else if (scanType === 'headers') {
      const result = await checkHttpHeaders(url);
      result.url = url;
      reportText = formatHeadersReport(result);
    } else if (scanType === 'ssl') {
      const result = await checkSsl(url);
      reportText = formatSslReport(result, url);
    } else if (scanType === 'sqli') {
      const result = await checkSqlInjection(url);
      const status = result.vulnerable ? '[VULNERABLE]' : '[SAFE]';
      const details = result.vulnerable
        ? result.details.map(d => `\`  ! ${d.substring(0, 33)}\``).join('\n')
        : '`  No SQL error patterns detected.     `';
      reportText = [
        '`────────────────────────────────────────`',
        '`  SQL INJECTION REPORT                 `',
        '`────────────────────────────────────────`',
        '',
        `*Target:* \`${url}\``,
        `*Status:* \`${status}\``,
        `*Tests:*  \`${result.tests.length} payloads sent\``,
        '',
        details,
      ].join('\n');
    } else if (scanType === 'xss') {
      const result = await checkXss(url);
      const status = result.vulnerable ? '[VULNERABLE]' : '[SAFE]';
      const details = result.vulnerable
        ? result.details.map(d => `\`  ! ${d.substring(0, 33)}\``).join('\n')
        : '`  No reflected XSS detected.          `';
      reportText = [
        '`────────────────────────────────────────`',
        '`  XSS SCAN REPORT                     `',
        '`────────────────────────────────────────`',
        '',
        `*Target:* \`${url}\``,
        `*Status:* \`${status}\``,
        `*Tests:*  \`${result.tests.length} payloads sent\``,
        '',
        details,
      ].join('\n');
    } else if (scanType === 'cors') {
      const result = await checkCors(url);
      const status = result.misconfigured ? '[MISCONFIGURED]' : '[SAFE]';
      reportText = [
        '`────────────────────────────────────────`',
        '`  CORS AUDIT REPORT                   `',
        '`────────────────────────────────────────`',
        '',
        `*Target:* \`${url}\``,
        `*Status:* \`${status}\``,
        `\`  Allow-Origin: ${String(result.allowOrigin || 'Not set').substring(0, 22).padEnd(22)}\``,
        '',
        ...result.details.map(d => `\`  ${d.substring(0, 37)}\``),
      ].join('\n');
    } else if (scanType === 'redirect') {
      const result = await checkOpenRedirect(url);
      const status = result.vulnerable ? '[VULNERABLE]' : '[SAFE]';
      reportText = [
        '`────────────────────────────────────────`',
        '`  OPEN REDIRECT REPORT                `',
        '`────────────────────────────────────────`',
        '',
        `*Target:* \`${url}\``,
        `*Status:* \`${status}\``,
        `*Tests:*  \`${result.tests.length} vectors tested\``,
        '',
        result.vulnerable
          ? '`  ! Open redirect to external domain  `'
          : '`  No open redirect detected.         `',
      ].join('\n');
    }

    await bot.editMessageText(reportText, {
      chat_id: chatId,
      message_id: scanning.message_id,
      parse_mode: 'Markdown',
      reply_markup: backToMain().reply_markup,
    });

  } catch (err) {
    console.error('[ERROR]', err.message);
    await bot.editMessageText(
      `\`  [ERROR] Scan failed.                 \`\n\n_${err.message.substring(0, 80)}_\n\n_Check if the target is reachable._`,
      {
        chat_id: chatId,
        message_id: scanning.message_id,
        parse_mode: 'Markdown',
        reply_markup: mainMenu().reply_markup,
      }
    );
  }
});

bot.on('polling_error', (err) => {
  console.error('[POLLING ERROR]', err.message);
});

process.on('SIGINT', () => {
  console.log('[INFO] Shutting down bot...');
  bot.stopPolling();
  process.exit(0);
});
