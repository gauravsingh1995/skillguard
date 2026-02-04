// Test file to verify prompt injection detection
// This file contains examples of LLM API usage that should be detected

const OpenAI = require('openai');
const Anthropic = require('@anthropic-ai/sdk');

// OpenAI API usage - should be detected
async function testOpenAI() {
  const openai = new OpenAI();

  const completion = await openai.chat.completions.create({
    model: "gpt-4",
    messages: [{ role: "user", content: "Hello" }]
  });

  return completion;
}

// Anthropic API usage - should be detected
async function testAnthropic() {
  const anthropic = new Anthropic();

  const message = await anthropic.messages.create({
    model: "claude-3-5-sonnet-20241022",
    max_tokens: 1024,
    messages: [{ role: "user", content: "Hello, Claude" }]
  });

  return message;
}

// Generic LLM API usage - should be detected
async function testGenericLLM() {
  const result = await sendMessage("Hello, AI");
  const generated = await generateContent("Create a story");
  const prompted = await prompt("Analyze this code");

  return { result, generated, prompted };
}

// Safe code - should NOT trigger prompt injection detection
function safeFunction() {
  console.log("This is safe code");
  return "No LLM API usage here";
}

module.exports = {
  testOpenAI,
  testAnthropic,
  testGenericLLM,
  safeFunction
};
