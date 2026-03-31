const http = require('http');
const SafeLM = require('./SafeLM');

const server = http.createServer((req, res) => {
  if (req.method === 'POST') {
    let rawBody = '';
    req.on('data', chunk => rawBody += chunk);
    req.on('end', () => {
      console.log("\n🌐 [Mock API Server] Received Payload:");
      console.log("   -->", rawBody);
      
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ 
         completion: "Processed successfully!"
      }));
    });
  }
});

server.listen(4001, async () => {
  console.log("🟢 Mock API is running on http://localhost:4001");

  // ============================================
  // 1. INITIALIZE THE SAAS SDK 
  // ============================================
  await SafeLM.init("SafeLM_customer_key_123");

  // ============================================
  // 2. TEST 1: INBOUND WAF (Simulate hacker request)
  // ============================================
  console.log("\n🧪 [TEST 1] Testing Global WAF Integration...");
  const maliciousInputFromHacker = '{"username": "admin", "password": "\' OR 1=1"}';
  
  try {
    // If the Customer's App (e.g. Express) tries to parse this JSON...
    const parsed = JSON.parse(maliciousInputFromHacker);
    console.log("❌ WAF FAILED: Payload passed through!", parsed);
  } catch (err) {
    console.log("✅ WAF SUCCESS: Bad Input instantly blocked!");
    console.log("   --> Caught:", err.message);
  }

  // ============================================
  // 3. TEST 2: OUTBOUND COMPRESSION & PII
  // ============================================
  console.log("\n🧪 [TEST 2] Testing ULIC-v2 Huffman Compression & PII Bounds...");
  
  // A long repetitive prompt that benefits easily from compression
  let longPrompt = "Please analyze this customer account. The customer is very important. ";
  for(let i=0; i<30; i++) {
    longPrompt += "The customer data requires customer verification and customer approval. ";
  }
  longPrompt += "Also call them at 555-123-4567. Do not mistake Unsplash image abc123def456 for a phone number!";

  const sensitivePayload = {
    prompt: longPrompt,
    model: "my-custom-llm"
  };

  const response = await fetch('http://localhost:4001/api/v1/llm', {
    method: 'POST',
    body: JSON.stringify(sensitivePayload)
  });

  const finalResult = await response.json();
  console.log("\n💻 [Customer App] Final fetch() returned:");
  console.log("   -->", finalResult);

  server.close();
  process.exit(0);
});
