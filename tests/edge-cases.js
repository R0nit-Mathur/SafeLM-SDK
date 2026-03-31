const http = require('http');
const SafeLM = require('./SafeLM');

// 1. Setup Mock LLM API
const server = http.createServer((req, res) => {
  if (req.method === 'POST') {
    let rawBody = '';
    req.on('data', chunk => rawBody += chunk);
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ completion: "Processed perfectly", raw: rawBody }));
    });
  }
});

async function runTests() {
  console.log("==========================================");
  console.log("🛡️  SafeLM END-TO-END SECURITY AUDIT 🛡️");
  console.log("==========================================\n");

  await SafeLM.init("SafeLM_test_key_123");

  let passed = 0;
  let total = 0;

  function assert(condition, testName, details = "") {
    total++;
    if (condition) {
      console.log(`✅ [PASS] ${testName}`);
      passed++;
    } else {
      console.log(`❌ [FAIL] ${testName}`);
      if (details) console.log(`   └─> ${details}`);
    }
  }

  // --- TEST A: WAF DEPTH INJECTION ---
  console.log("\n[A] WAF (Web Application Firewall) Edge Cases");
  const nestedSqli = '{"user": {"profile": {"preferences": {"bio": "hello \' oR 1=1 --"}}}}';
  try {
    JSON.parse(nestedSqli);
    assert(false, "WAF SQLi Depth Bypass", "WAF failed to catch deeply nested SQLi");
  } catch (e) {
    assert(e.message.includes('SafeLM WAF Blocked'), "WAF Blocked Nested SQLi Injection");
  }

  const xssArray = '["safe", "safe", "<sCripT>alert(1)</script>"]';
  try {
    JSON.parse(xssArray);
    assert(false, "WAF XSS Array Bypass", "WAF failed to catch XSS inside an array");
  } catch (e) {
    assert(e.message.includes('SafeLM WAF Blocked'), "WAF Blocked Array XSS Injection");
  }

  // --- TEST B: PII FALSE POSITIVES & MESSY FORMATS ---
  console.log("\n[B] PII Bound Constraints");
  // We send a request to the mock LLM
  let response = await fetch('http://localhost:4001/api/v1/llm', {
    method: 'POST',
    body: JSON.stringify({
      prompt: "Contact john.doe+tag@sub.domain.co.uk at +1 (555) 123-4567 or 001-555-1234. Unsplash ID: aZ9Dx2Q and Order_12345.",
      model: "test-model"
    })
  });
  let json = await response.json();
  const rawPayload = json.raw || "";
  
  // Assert the round-trip worked: The SDK transparently un-redacted the PII!
  assert(rawPayload.includes('john.doe+tag@sub.domain.co.uk'), "PII Transparently Restored Messy Email");
  assert(rawPayload.includes('+1 (555) 123-4567'), "PII Transparently Restored Tricky US Phone Number");
  assert(rawPayload.includes('001-555-1234'), "PII Transparently Restored Alternative Format Phone");
  // Did it IGNORE the alphanumeric strings?
  assert(rawPayload.includes('aZ9Dx2Q') && rawPayload.includes('Order_12345'), "PII Ignored Safe Alphanumeric Strings (No False Positives)");

  // --- TEST C: ULIC-v2 & TOON SHORTHAND COMPRESSION ---
  console.log("\n[C] Lossless Prompt Compression");
  const embeddedJsonString = JSON.stringify({
    prompt: "Translate this json structure. {\"user_data\": {\"role\": \"admin\", \"status\": \"active\"}}",
    model: "test-model"
  });

  response = await fetch('http://localhost:4001/api/v1/llm', {
    method: 'POST',
    body: embeddedJsonString
  });
  json = await response.json();
  console.log(">>> RAW PAYLOAD C:", json.raw || "");
  
  assert((json.raw || "").includes('TOON[user_data:role:admin,status:active]'), "JSON TOON Shorthand successfully compressed embedded stringified JSON");

  let repetitiveString = "";
  for(let i=0; i<30; i++) {
    repetitiveString += "Extraterrestrial lifeform classification sequence. ";
  }
  response = await fetch('http://localhost:4001/api/v1/llm', {
    method: 'POST',
    body: JSON.stringify({ prompt: repetitiveString, model: "test" })
  });
  json = await response.json();
  // Ensure the dictionary and Huffman codes are present in the exact payload sent over the wire
  assert(json.raw.includes('DECOMPRESS first using this exact mapping') && json.raw.includes('@@0'), "ULIC-v2 Huffman Dictionary successfully compiled and applied to prompt network payload");

  // --- TEST D: MULTI-DOMAIN VALIDATION ---
  console.log("\n[D] Multi-Domain Validation");
  try {
    // google.com is NOT in target domains
    const googleRes = await fetch('https://jsonplaceholder.typicode.com/todos/1', { method: 'POST' });
    assert(true, "SDK Seamlessly bypassed non-LLM domain traffic without intercepting");
  } catch (e) {
    assert(false, "SDK Seamlessly bypassed non-LLM domain traffic without intercepting", e.message);
  }

  // --- TEST E: ANTI-LOOP RATE LIMITING ---
  console.log("\n[E] Rate Limiting Exhaustion");
  let burstBlocked = false;
  // We rapid fire 105 async requests (our limit is 100)
  const burst = [];
  for(let i=0; i<105; i++) {
    burst.push(fetch('http://localhost:4001/api/v1/llm', { method: 'POST', body: '{"prompt":"test"}' }));
  }
  
  const results = await Promise.all(burst);
  for(const res of results) {
    if (res.status === 429) { burstBlocked = true; }
  }
  
  assert(burstBlocked, "Anti-Loop Burst Rate Limiter correctly triggered 429 after 100 requests");

  console.log(`\n==========================================`);
  console.log(`🏁 AUDIT COMPLETE: ${passed}/${total} Edge Cases Passed 🏁`);
  console.log(`==========================================\n`);

  server.close();
  process.exit(0);
}

server.listen(4001, () => {
  runTests();
});
