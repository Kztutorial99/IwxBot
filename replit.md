# VulnScan Telegram Bot

A professional Telegram bot for web vulnerability scanning, analysis, and reporting.

## Features
- SQL Injection detection
- XSS vulnerability scanning
- HTTP security headers analysis
- SSL/TLS certificate check
- Open redirect testing
- CORS misconfiguration detection
- Formatted table reports

## Project Structure
- `api/webhook.js` - Telegram webhook handler (Vercel serverless)
- `lib/scanner.js` - Web vulnerability scanner core
- `lib/reporter.js` - Report formatter
- `lib/keyboards.js` - Telegram inline keyboard menus
- `lib/messages.js` - Message templates
- `bot.js` - Local polling mode (development)
- `server.js` - Express server for webhook (alternative)

## Deployment
- **Vercel**: Webhook-based via `api/webhook.js`
- **Replit VM**: Long-polling via `bot.js`

## Environment Variables
- `TELEGRAM_BOT_TOKEN` - Bot token from @BotFather
- `WEBHOOK_URL` - Public URL for webhook (Vercel domain)

## User Preferences
- No emojis in bot messages
- Clean, professional table-formatted output
- Full inline keyboard navigation
