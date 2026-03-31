const assert = require('assert');
const test = require('node:test');
const { redactObject, restoreObject, cleanupVault } = require('../src/pii');

test('Bidirectional PII Redaction', () => {
  const reqId = 'test-req-123';
  
  const payload = {
    messages: [
      { role: "user", content: "My email is john.doe@email.com and phone is 987-654-3210." }
    ]
  };

  // 1. Redact
  const redacted = redactObject(payload, reqId);
  
  assert.notStrictEqual(redacted.messages[0].content, payload.messages[0].content);
  assert.ok(redacted.messages[0].content.includes('[REDACTED-EMAIL-1]'));
  assert.ok(redacted.messages[0].content.includes('[REDACTED-PHONE-1]'));
  
  // 2. Mock LLM Response (echoing back the prompt)
  const llmResponse = {
    choices: [
      { message: { content: "I see your email is [REDACTED-EMAIL-1] and phone is [REDACTED-PHONE-1]." } }
    ]
  };

  // 3. Restore
  const restored = restoreObject(llmResponse, reqId);
  
  assert.ok(restored.choices[0].message.content.includes('john.doe@email.com'));
  assert.ok(restored.choices[0].message.content.includes('987-654-3210'));

  // 4. Cleanup
  cleanupVault(reqId);
});
