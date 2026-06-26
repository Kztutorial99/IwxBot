// Inline keyboard menus for Telegram bot

const mainMenu = () => ({
  reply_markup: {
    inline_keyboard: [
      [
        { text: '[ SCAN TARGET ]', callback_data: 'menu_scan' },
        { text: '[ QUICK SCAN ]', callback_data: 'menu_quick' },
      ],
      [
        { text: '[ FULL ANALYSIS ]', callback_data: 'menu_full' },
        { text: '[ REPORTS ]', callback_data: 'menu_reports' },
      ],
      [
        { text: '[ MODULES ]', callback_data: 'menu_modules' },
        { text: '[ SETTINGS ]', callback_data: 'menu_settings' },
      ],
      [
        { text: '[ HELP ]', callback_data: 'menu_help' },
        { text: '[ ABOUT ]', callback_data: 'menu_about' },
      ],
    ],
  },
});

const scanMenu = () => ({
  reply_markup: {
    inline_keyboard: [
      [
        { text: '>> Full Scan', callback_data: 'scan_full' },
      ],
      [
        { text: '>> Headers Only', callback_data: 'scan_headers' },
        { text: '>> SSL Check', callback_data: 'scan_ssl' },
      ],
      [
        { text: '>> SQLi Test', callback_data: 'scan_sqli' },
        { text: '>> XSS Test', callback_data: 'scan_xss' },
      ],
      [
        { text: '>> CORS Check', callback_data: 'scan_cors' },
        { text: '>> Redirect Test', callback_data: 'scan_redirect' },
      ],
      [
        { text: '<< Back to Main', callback_data: 'menu_main' },
      ],
    ],
  },
});

const modulesMenu = () => ({
  reply_markup: {
    inline_keyboard: [
      [
        { text: 'SQL Injection', callback_data: 'info_sqli' },
        { text: 'XSS Scanner', callback_data: 'info_xss' },
      ],
      [
        { text: 'Header Analysis', callback_data: 'info_headers' },
        { text: 'SSL/TLS Check', callback_data: 'info_ssl' },
      ],
      [
        { text: 'CORS Audit', callback_data: 'info_cors' },
        { text: 'Open Redirect', callback_data: 'info_redirect' },
      ],
      [
        { text: '<< Back to Main', callback_data: 'menu_main' },
      ],
    ],
  },
});

const backToMain = () => ({
  reply_markup: {
    inline_keyboard: [
      [
        { text: '<< Back to Main', callback_data: 'menu_main' },
        { text: '[ SCAN AGAIN ]', callback_data: 'menu_scan' },
      ],
    ],
  },
});

const reportMenu = (sessionId) => ({
  reply_markup: {
    inline_keyboard: [
      [
        { text: '[ View Full Report ]', callback_data: `report_full_${sessionId}` },
      ],
      [
        { text: '[ Export Summary ]', callback_data: `report_summary_${sessionId}` },
        { text: '[ Scan Again ]', callback_data: 'menu_scan' },
      ],
      [
        { text: '<< Main Menu', callback_data: 'menu_main' },
      ],
    ],
  },
});

const confirmScan = (url, mode) => ({
  reply_markup: {
    inline_keyboard: [
      [
        { text: '[  CONFIRM SCAN  ]', callback_data: `confirm_${mode}_${Buffer.from(url).toString('base64').substring(0, 40)}` },
      ],
      [
        { text: '[ Cancel ]', callback_data: 'menu_main' },
      ],
    ],
  },
});

module.exports = { mainMenu, scanMenu, modulesMenu, backToMain, reportMenu, confirmScan };
