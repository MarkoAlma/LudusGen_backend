import {
  buildContext,
  getMessagesForSummary,
  getUnsummarizedMessages,
  RECENT_MESSAGE_WINDOW,
  SUMMARY_TRIGGER_COUNT,
} from "../contextBuilder.js";

let passed = 0;
let failed = 0;

function assert(condition, label) {
  if (condition) {
    console.log(`  PASS: ${label}`);
    passed++;
  } else {
    console.error(`  FAIL: ${label}`);
    failed++;
  }
}

function createMessages(count) {
  return Array.from({ length: count }, (_, index) => ({
    role: index % 2 === 0 ? "user" : "assistant",
    content: `message-${index + 1}`,
  }));
}

console.log("\nScenario 1: summary picks the oldest 20 when 40 raw messages exist");
{
  const messages = createMessages(40);
  const chunk = getMessagesForSummary(messages, 0);
  assert(chunk.length === 20, `Chunk length should be 20, got ${chunk.length}`);
  assert(chunk[0].content === "message-1", `First summarized message should be message-1, got ${chunk[0]?.content}`);
  assert(chunk[19].content === "message-20", `Last summarized message should be message-20, got ${chunk[19]?.content}`);
}

console.log("\nScenario 2: unsummarized backlog below 40 should not trigger summary");
{
  const messages = createMessages(39);
  const chunk = getMessagesForSummary(messages, 0);
  assert(chunk.length === 0, `Chunk length should be 0 before threshold, got ${chunk.length}`);
}

console.log("\nScenario 3: without summary the full backlog stays in context until 40 messages");
{
  const messages = createMessages(30);
  const context = buildContext(messages, null, 0, { role: "user", content: "latest-user-message" }, "System prompt");
  const chatMessages = context.filter((message) => message.role !== "system");
  assert(chatMessages.length === 31, `Chat message count should be 31 before summary exists, got ${chatMessages.length}`);
  assert(chatMessages[0].content === "message-1", `Context should still include the oldest raw message, got ${chatMessages[0]?.content}`);
  assert(chatMessages[29].content === "message-30", `Context should still include message-30, got ${chatMessages[29]?.content}`);
  assert(chatMessages[30].content === "latest-user-message", `Last chat entry should be the new message, got ${chatMessages[30]?.content}`);
}

console.log("\nScenario 4: with summary, the unsummarized backlog keeps growing until the next 40-message threshold");
{
  const messages = createMessages(60);
  const context = buildContext(messages, "Older summary", 20, { role: "user", content: "latest-user-message" }, "System prompt");
  const chatMessages = context.filter((message) => message.role !== "system");
  assert(context[0].role === "system", "First context entry should be the system prompt");
  assert(context[1].role === "system", "Second context entry should be the conversation summary");
  assert(chatMessages.length === 41, `Chat message count should be 41 (40 unsummarized + new one), got ${chatMessages.length}`);
  assert(chatMessages[0].content === "message-21", `Unsummarized backlog should start at message-21, got ${chatMessages[0]?.content}`);
  assert(chatMessages[39].content === "message-60", `Unsummarized backlog should end at message-60, got ${chatMessages[39]?.content}`);
  assert(chatMessages[40].content === "latest-user-message", `Last chat entry should be the new message, got ${chatMessages[40]?.content}`);
}

console.log("\nScenario 5: helper exposes the current raw backlog after summarized messages");
{
  const messages = createMessages(80);
  const unsummarized = getUnsummarizedMessages(messages, 60);
  assert(unsummarized.length === 20, `Unsummarized message count should be 20, got ${unsummarized.length}`);
  assert(unsummarized[0].content === "message-61", `First unsummarized message should be message-61, got ${unsummarized[0]?.content}`);
  assert(unsummarized[19].content === "message-80", `Last unsummarized message should be message-80, got ${unsummarized[19]?.content}`);
}

console.log("\nScenario 6: exported constants match the agreed backend policy");
{
  assert(RECENT_MESSAGE_WINDOW === 20, `RECENT_MESSAGE_WINDOW should be 20, got ${RECENT_MESSAGE_WINDOW}`);
  assert(SUMMARY_TRIGGER_COUNT === 40, `SUMMARY_TRIGGER_COUNT should be 40, got ${SUMMARY_TRIGGER_COUNT}`);
}

console.log(`\n${"=".repeat(60)}`);
console.log(`Results: ${passed} passed, ${failed} failed, ${passed + failed} total`);
if (failed > 0) {
  console.error("CONTEXT BUILDER TESTS FAILED");
  process.exit(1);
} else {
  console.log("ALL CONTEXT BUILDER TESTS PASSED");
}
