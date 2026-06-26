# IwxBot - VulnScan Telegram Bot

Professional web vulnerability scanning bot for Telegram.

## Features

| Module            | Description                                       | Risk Level |
|-------------------|---------------------------------------------------|------------|
| SQL Injection     | Detects SQL error patterns via crafted payloads   | CRITICAL   |
| XSS Scanner       | Checks for reflected cross-site scripting         | HIGH       |
| Headers Analyzer  | Audits 10 HTTP security headers                   | MEDIUM     |
| SSL/TLS Check     | Validates HTTPS and redirect enforcement          | HIGH       |
| CORS Auditor      | Detects CORS misconfiguration via Origin spoofing | HIGH       |
| Open Redirect     | Tests for unvalidated redirect parameters         | MEDIUM     |

## Bot Commands

| Command         | Description              |
|-----------------|--------------------------|
| `/start`        | Open main menu           |
| `/scan <url>`   | Quick full scan          |
| `/help`         | Show usage instructions  |
| `/cancel`       | Cancel current operation |

## Setup

### 1. Clone the repository
```bash
git clone https://github.com/Kztutorial99/IwxBot.git
cd IwxBot
npm install
```

### 2. Set environment variables
```bash
cp .env.example .env
# Edit .env with your TELEGRAM_BOT_TOKEN
```

### 3. Run locally (polling mode)
```bash
npm start
```

## Deployment

### Vercel (Webhook Mode)
1. Push to GitHub
2. Import project in [vercel.com](https://vercel.com)
3. Add `TELEGRAM_BOT_TOKEN` in Vercel environment variables
4. Set the webhook after deployment:
   ```
   https://api.telegram.org/bot<TOKEN>/setWebhook?url=https://<your-domain>.vercel.app/api/webhook
   ```

### Replit (Polling Mode)
1. Add `TELEGRAM_BOT_TOKEN` as a Replit Secret
2. Set run command to `node bot.js`
3. Deploy as VM type

## Project Structure

```
IwxBot/
├── api/
│   └── webhook.js       # Vercel serverless webhook handler
├── lib/
│   ├── scanner.js       # Vulnerability scanning engine
│   ├── messages.js      # Telegram message templates
│   ├── keyboards.js     # Inline keyboard menus
│   └── sessions.js      # Session state management
├── bot.js               # Local polling bot (development)
├── vercel.json          # Vercel deployment config
├── package.json
└── README.md
```

## Disclaimer

This tool is for authorized security testing only. Only scan targets you own or have explicit written permission to test. Unauthorized scanning may be illegal in your jurisdiction.
