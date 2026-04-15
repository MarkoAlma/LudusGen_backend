// ═══════════════════════════════════════════════════════
// contextBuilder.js — Kontextus építés a backenden
// ═══════════════════════════════════════════════════════

const RECENT_MESSAGE_COUNT = 20;
const CONTEXT_LIMIT_RATIO = 0.8;

// Rough token estimation: ~3 chars per token for Hungarian text
function estimateTokens(text) {
  if (!text) return 0;
  return Math.ceil(text.length / 3);
}

function estimateContextTokens(messages) {
  return messages.reduce((sum, m) => sum + estimateTokens(m.content), 0);
}

/**
 * Build the context for an AI API call.
 * @param {Array} sessionMessages - Recent messages from Firestore (without the new one)
 * @param {Object|null} summary - { text, messageCount } from session doc
 * @param {Object} newMessage - { role: 'user', content: '...' }
 * @param {string|null} systemPrompt - Model's default system prompt
 * @returns {Array} Optimized message array for the AI API
 */
export function buildContext(sessionMessages, summary, newMessage, systemPrompt) {
  const context = [];

  // 1. System prompt
  if (systemPrompt) {
    context.push({ role: 'system', content: systemPrompt });
  }

  // 2. Summary (if exists)
  if (summary?.text) {
    context.push({ role: 'system', content: `[Conversation Summary]\n${summary.text}` });
  }

  // 3. Recent messages (last N from Firestore)
  const recent = sessionMessages.slice(-RECENT_MESSAGE_COUNT);
  context.push(...recent);

  // 4. New user message (guard against null/undefined)
  if (newMessage?.content) {
    context.push(newMessage);
  }

  return context;
}

/**
 * Trim messages to fit within the context limit.
 * Keeps system messages, removes oldest user/assistant messages.
 */
export function trimToContextLimit(messages, maxTokens) {
  let total = estimateContextTokens(messages);
  if (total <= maxTokens) return messages;

  const systemMsgs = messages.filter(m => m.role === 'system');
  const chatMsgs = messages.filter(m => m.role !== 'system');

  while (chatMsgs.length > 2 && estimateContextTokens([...systemMsgs, ...chatMsgs]) > maxTokens) {
    chatMsgs.shift();
  }

  return [...systemMsgs, ...chatMsgs];
}

export { RECENT_MESSAGE_COUNT, CONTEXT_LIMIT_RATIO };
