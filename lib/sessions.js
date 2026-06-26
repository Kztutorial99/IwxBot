// Simple in-memory session management

const sessions = new Map();
const reports = new Map();

function getSession(chatId) {
  if (!sessions.has(chatId)) {
    sessions.set(chatId, { state: 'idle', scanType: null, data: {} });
  }
  return sessions.get(chatId);
}

function setSession(chatId, data) {
  sessions.set(chatId, { ...getSession(chatId), ...data });
}

function clearSession(chatId) {
  sessions.set(chatId, { state: 'idle', scanType: null, data: {} });
}

function saveReport(sessionId, report) {
  reports.set(sessionId, report);
}

function getReport(sessionId) {
  return reports.get(sessionId);
}

function generateSessionId() {
  return Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
}

module.exports = { getSession, setSession, clearSession, saveReport, getReport, generateSessionId };
