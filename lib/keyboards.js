// Inline keyboard menus — IwxBot v2

const mainMenu = () => ({
  reply_markup: {
    inline_keyboard: [
      [
        { text: '>> SCAN TARGET',   callback_data: 'menu_scan' },
        { text: '>> QUICK SCAN',    callback_data: 'menu_quick' },
      ],
      [
        { text: '>> FULL ANALYSIS', callback_data: 'scan_full' },
        { text: '>> MODULES',       callback_data: 'menu_modules' },
      ],
      [
        { text: '>> REPORTS',       callback_data: 'menu_reports' },
        { text: '>> SETTINGS',      callback_data: 'menu_settings' },
      ],
      [
        { text: '>> HELP',          callback_data: 'menu_help' },
        { text: '>> ABOUT',         callback_data: 'menu_about' },
      ],
    ],
  },
});

const scanMenu = () => ({
  reply_markup: {
    inline_keyboard: [
      [
        { text: '[*] Full Scan',    callback_data: 'scan_full' },
      ],
      [
        { text: '[S] SSL / TLS',    callback_data: 'scan_ssl' },
        { text: '[H] Headers',      callback_data: 'scan_headers' },
      ],
      [
        { text: '[i] SQL Inject',   callback_data: 'scan_sqli' },
        { text: '[x] XSS Test',     callback_data: 'scan_xss' },
      ],
      [
        { text: '[c] CORS Audit',   callback_data: 'scan_cors' },
        { text: '[r] Redirect',     callback_data: 'scan_redirect' },
      ],
      [
        { text: '<< Back',          callback_data: 'menu_main' },
      ],
    ],
  },
});

const modulesMenu = () => ({
  reply_markup: {
    inline_keyboard: [
      [
        { text: 'SQL Injection',    callback_data: 'info_sqli' },
        { text: 'XSS Scanner',      callback_data: 'info_xss' },
      ],
      [
        { text: 'Headers Audit',    callback_data: 'info_headers' },
        { text: 'SSL / TLS',        callback_data: 'info_ssl' },
      ],
      [
        { text: 'CORS Audit',       callback_data: 'info_cors' },
        { text: 'Open Redirect',    callback_data: 'info_redirect' },
      ],
      [
        { text: '<< Back',          callback_data: 'menu_main' },
      ],
    ],
  },
});

const backToMain = () => ({
  reply_markup: {
    inline_keyboard: [
      [
        { text: '<< Main Menu',     callback_data: 'menu_main' },
        { text: '>> Scan Again',    callback_data: 'menu_scan' },
      ],
    ],
  },
});

const backOnly = () => ({
  reply_markup: {
    inline_keyboard: [
      [{ text: '<< Main Menu', callback_data: 'menu_main' }],
    ],
  },
});

module.exports = { mainMenu, scanMenu, modulesMenu, backToMain, backOnly };
