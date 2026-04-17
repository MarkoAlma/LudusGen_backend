// ═══════════════════════════════════════════════════════
// contextBuilder.js — Kontextus építés a backenden
// ═══════════════════════════════════════════════════════

const RECENT_MESSAGE_WINDOW = 20;
const SUMMARY_TRIGGER_COUNT = 40;
const CONTEXT_LIMIT_RATIO = 0.8;

function estimateTokens(text) {
  if (!text) return 0;
  return Math.ceil(String(text).length / 3);
}

function estimateContentTokens(content) {
  if (typeof content === 'string') {
    return estimateTokens(content);
  }

  if (Array.isArray(content)) {
    return content.reduce((sum, part) => {
      if (part?.type === 'text') {
        return sum + estimateTokens(part.text);
      }
      return sum;
    }, 0);
  }

  return 0;
}

function estimateContextTokens(messages) {
  return messages.reduce((sum, message) => sum + estimateContentTokens(message.content), 0);
}

export function getUnsummarizedMessages(allMessages, summarizedMessageCount = 0) {
  return allMessages.slice(summarizedMessageCount);
}

export function getMessagesForSummary(allMessages, summarizedMessageCount = 0) {
  const unsummarizedMessages = getUnsummarizedMessages(allMessages, summarizedMessageCount);
  if (unsummarizedMessages.length < SUMMARY_TRIGGER_COUNT) {
    return [];
  }

  return unsummarizedMessages.slice(0, RECENT_MESSAGE_WINDOW);
}

export function buildContext(allMessages, summaryText, summarizedMessageCount = 0, newMessage, systemPrompt) {
  const context = [];

  if (systemPrompt) {
    context.push({ role: 'system', content: systemPrompt });
  }

  if (summaryText) {
    context.push({ role: 'system', content: `[Conversation Summary]\n${summaryText}` });
  }

  const unsummarizedMessages = getUnsummarizedMessages(allMessages, summarizedMessageCount);
  context.push(...unsummarizedMessages);

  if (newMessage?.content) {
    context.push(newMessage);
  }

  return context;
}

export function trimToContextLimit(messages, maxTokens) {
  if (estimateContextTokens(messages) <= maxTokens) {
    return messages;
  }

  const systemMessages = messages.filter((message) => message.role === 'system');
  const chatMessages = messages.filter((message) => message.role !== 'system');

  while (chatMessages.length > 2 && estimateContextTokens([...systemMessages, ...chatMessages]) > maxTokens) {
    chatMessages.shift();
  }

  return [...systemMessages, ...chatMessages];
}

export { RECENT_MESSAGE_WINDOW, SUMMARY_TRIGGER_COUNT, CONTEXT_LIMIT_RATIO };
