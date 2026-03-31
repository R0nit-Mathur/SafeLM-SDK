/**
 * SafeLM Security SDK (Node.js) - Paid Edition
 * 
 * Usage:
 * const SafeLM = require('./SafeLM');
 * SafeLM.init('YOUR_SafeLM_API_KEY');
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// --- Global State ---
let isInitialized = false;
let CONFIG = {
  SafeLMEnabled: false,
  enablePiiRedaction: false,
  enablePromptCompression: false,
  enableLLMLingua: false,
  enableJsonShorthand: false,
  enableCaching: false,
  enableWAF: false,
  enableCrashProtection: false,
  rateLimitPerMinute: 0,
  telemetryEndpoint: "",
  targetDomains: []
};

// --- In-Memory Tools ---
const rateLimiter = { count: 0, resetAt: Date.now() + 60000 };
const vaultStore = {}; 
const llmResponseCache = new Map(); // payloadHash -> { data, expiresAt }
const telemetryStats = { tokensSaved: 0, threatsBlocked: 0, cachesHit: 0 };
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

// --- Internal Utilities ---
function hashString(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

// --- PII Redaction Engine ---
const PII_PATTERNS = {
  EMAIL: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
  PHONE: /\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
};

function redactText(text, reqId) {
  if (!CONFIG.enablePiiRedaction || typeof text !== 'string') return text;
  if (!vaultStore[reqId]) vaultStore[reqId] = { map: {}, counters: { EMAIL: 0, PHONE: 0 } };
  
  const vault = vaultStore[reqId];
  let redacted = text;
  
  for (const [type, regex] of Object.entries(PII_PATTERNS)) {
    redacted = redacted.replace(regex, (match) => {
      vault.counters[type]++;
      const placeholder = `[REDACTED-${type}-${vault.counters[type]}]`;
      vault.map[placeholder] = match;
      return placeholder;
    });
  }
  return redacted;
}

function restoreText(text, reqId) {
  if (!CONFIG.enablePiiRedaction || typeof text !== 'string') return text;
  const vault = vaultStore[reqId];
  if (!vault) return text;

  let restored = text;
  for (const [placeholder, original] of Object.entries(vault.map)) {
    restored = restored.split(placeholder).join(original);
  }
  return restored;
}

function redactObject(obj, reqId) {
  if (typeof obj === 'string') return redactText(obj, reqId);
  if (Array.isArray(obj)) return obj.map(item => redactObject(item, reqId));
  if (typeof obj === 'object' && obj !== null) {
    const newObj = {};
    for (const [k, v] of Object.entries(obj)) newObj[k] = redactObject(v, reqId);
    return newObj;
  }
  return obj;
}

function restoreObject(obj, reqId) {
  if (typeof obj === 'string') return restoreText(obj, reqId);
  if (Array.isArray(obj)) return obj.map(item => restoreObject(item, reqId));
  if (typeof obj === 'object' && obj !== null) {
    const newObj = {};
    for (const [k, v] of Object.entries(obj)) newObj[k] = restoreObject(v, reqId);
    return newObj;
  }
  return obj;
}

// --- TOON JSON Shorthand Converter ---
const originalJsonParse = JSON.parse;

function convertJsonToShorthand(text) {
  if (!CONFIG.enableJsonShorthand || typeof text !== 'string') return text;
  
  // Try to find large JSON blocks inside the prompt string
  const jsonRegex = /(\{[\s\S]*\}|\[[\s\S]*\])/g;
  return text.replace(jsonRegex, (match) => {
    try {
      const parsed = originalJsonParse(match);
      if (typeof parsed !== 'object' || parsed === null) return match;
      
      function toTightShorthand(obj) {
        if (Array.isArray(obj)) return `[` + obj.map(toTightShorthand).join('|') + `]`;
        if (typeof obj === 'object' && obj !== null) {
          return Object.entries(obj).map(([k,v]) => `${k}:${toTightShorthand(v)}`).join(',');
        }
        return `${obj}`;
      }
      
      const shorthand = "TOON[" + toTightShorthand(parsed) + "]";
      if (shorthand.length < match.length) {
         console.log(`[SafeLM SDK] ✂️  Converted embedded JSON object to TOON shorthand (${match.length} -> ${shorthand.length} chars)`);
         return shorthand;
      }
      return match;
    } catch(e) {
      return match; 
    }
  });
}

// --- LLM Lingua Fast Lexical Compressor ---
// Safe context preserving stop-word removal.
const STOP_WORDS = /\b(?:a|an|the|very|actually|basically|literally|just|really)\b /gi;

function applyLLMLingua(text) {
  if (!CONFIG.enableLLMLingua || typeof text !== 'string') return text;
  
  const originalLen = text.length;
  // Compress multiple spaces and strip filler words safely
  let compressed = text.replace(STOP_WORDS, '').replace(/\s{2,}/g, ' ').trim();
  
  if (compressed.length < originalLen) {
    const saved = originalLen - compressed.length;
    telemetryStats.tokensSaved += Math.floor(saved / 4); // approx 4 chars per token
    console.log(`[SafeLM SDK] ✂️  LLM-Lingua Lexical compression saved ${saved} characters.`);
    return compressed;
  }
  return text;
}

// --- ULIC-v2 Huffman Prompt Compression ---
function compressPrompt(text) {
  // First apply semantic Lingua compression to strip garbage
  text = applyLLMLingua(text);

  // Then apply the TOON json shorthand if enabled
  text = convertJsonToShorthand(text);

  if (!CONFIG.enablePromptCompression || typeof text !== 'string' || text.length < 150) return text;
  
  const words = text.match(/\b[a-zA-Z]{5,}\b/g);
  if (!words) return text;
  
  const freq = {};
  for (const w of words) { freq[w] = (freq[w] || 0) + 1; }
  
  const sorted = Object.keys(freq)
    .filter(w => freq[w] > 1)
    .sort((a, b) => (freq[b] * b.length) - (freq[a] * a.length))
    .slice(0, 30);
    
  if (sorted.length === 0) return text;
  
  const codeChars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  const mapping = {};
  const reverseMap = {};
  
  sorted.forEach((word, i) => {
    const code = `@@${codeChars[i]}`;
    mapping[word] = code;
    reverseMap[code] = word;
  });
  
  let encoded = text;
  for (const [word, code] of Object.entries(mapping)) {
    encoded = encoded.replace(new RegExp(`\\b${word}\\b`, 'g'), code);
  }
  
  if (encoded.length >= text.length) return text; 
  
  const dictStr = JSON.stringify(reverseMap, null, 0);
  const savedChars = text.length - encoded.length;
  telemetryStats.tokensSaved += Math.floor(savedChars / 4);
  console.log(`[SafeLM SDK] 📦 ULIC-v2 Compression saved ${savedChars} characters natively!`);
  
  return `DECOMPRESS first using this exact mapping (replace codes with values), then process the original request:\nDICT: ${dictStr}\nENCODED:\n${encoded}`;
}

function applyULICCompression(obj) {
  if (typeof obj === 'string') return compressPrompt(obj);
  if (Array.isArray(obj)) return obj.map(applyULICCompression);
  if (typeof obj === 'object' && obj !== null) {
    const newObj = {};
    for (const [k, v] of Object.entries(obj)) {
      if (k === 'prompt' || k === 'content' || k === 'text' || k === 'system_prompt') {
        newObj[k] = applyULICCompression(v);
      } else {
        newObj[k] = v; 
      }
    }
    return newObj;
  }
  return obj;
}


// --- Inbound WAF Protection (Monkey-Patching JSON.parse) ---
const WAF_RULES = {
  SQLI: /(?:UNION(?:%20|\s)+SELECT|DROP(?:%20|\s)+TABLE|INSERT(?:%20|\s)+INTO|UPDATE(?:%20|\s)+.*?SET|DELETE(?:%20|\s)+FROM|'(?:%20|\s)+(?:OR|AND)(?:%20|\s)+.*?=)/i,
  XSS: /(?:<script.*?>|<\/script>|<iframe.*?>|<\/iframe>|<(?:img|svg|body|html).*?(?:onload|onerror|onmouseover)=)/i,
  RCE: /(?:\b(?:ping|curl|wget|bash|sh|powershell)\b.*?(?:;|\&|\|)|`.*?(?:ping|curl|wget|bash|sh|powershell).*?`)/i,
  LFI: /(?:\.\.\/|\.\.\\|etc\/passwd|windows\\system32|cmd\.exe)/i,
  NOSQL: /(?:\$where|\$ne|\$gt|\$gte|\$lt|\$lte|\$in)/i
};

function scanWAFObject(obj) {
  if (typeof obj === 'string') {
    // Basic ReDoS safety cap for regex checks
    const safeStr = obj.length > 50000 ? obj.substring(0, 50000) : obj;
    for (const [ruleName, regex] of Object.entries(WAF_RULES)) {
      if (regex.test(safeStr)) {
        telemetryStats.threatsBlocked++;
        console.error(`[SafeLM SDK] 🚨 WAF BLOCKED PAYLOAD! Detected ${ruleName} Attack signature!`);
        throw new SyntaxError(`SafeLM WAF Blocked Payload: Potential ${ruleName} detected.`);
      }
    }
  } else if (Array.isArray(obj)) {
    obj.forEach(scanWAFObject);
  } else if (typeof obj === 'object' && obj !== null) {
    Object.values(obj).forEach(scanWAFObject);
  }
}

function applyWAFMonkeyPatch() {
  if (JSON && !JSON.__SafeLM_patched) {
    JSON.parse = function (text, reviver) {
      const parsed = originalJsonParse.apply(this, arguments);
      if (isInitialized && CONFIG.enableWAF) {
        scanWAFObject(parsed);
      }
      return parsed;
    };
    JSON.__SafeLM_patched = true;
    console.log('[SafeLM SDK] 🛡️ Global JSON Parser WAF Hook Activated.');
  }
}

// --- Outbound Interceptor (Monkey-Patching) ---
let originalFetch = null;

function applyOutboundMonkeyPatch() {
  if (global.fetch && !originalFetch) {
    originalFetch = global.fetch;
    
    global.fetch = async function (url, options = {}) {
      if (!isInitialized || !CONFIG.SafeLMEnabled) {
        return originalFetch.apply(this, arguments);
      }

      const urlString = url.toString();
      const isTargetDomain = CONFIG.targetDomains.some(domain => urlString.includes(domain));
      
      if (!isTargetDomain || options.method !== 'POST') {
        return originalFetch.apply(this, arguments);
      }

      // Rate Limiting Protection
      if (Date.now() > rateLimiter.resetAt) {
        rateLimiter.count = 0;
        rateLimiter.resetAt = Date.now() + 60000;
      }
      rateLimiter.count++;
      
      if (rateLimiter.count > CONFIG.rateLimitPerMinute) {
        console.error(`[SafeLM SDK] 🚨 Rate Limit Exceeded: Application bounded to ${CONFIG.rateLimitPerMinute} reqs/min.`);
        return Promise.resolve(new Response(JSON.stringify({
          error: "SafeLM SDK - Outbound Rate Limit Exceeded"
        }), { status: 429 }));
      }

      const reqId = crypto.randomUUID();
      let bodyWasModified = false;
      let payloadHash = null;

      try {
        if (options.body && typeof options.body === 'string') {
          // Exact Semantic Caching Layer Check
          if (CONFIG.enableCaching) {
            payloadHash = hashString(options.body);
            const cachedEntry = llmResponseCache.get(payloadHash);
            if (cachedEntry && Date.now() < cachedEntry.expiresAt) {
               telemetryStats.cachesHit++;
               console.log(`[SafeLM SDK] ⚡ Semantic Cache HIT! Returning instant local response for payload, saving 100% tokens!`);
               return new Response(JSON.stringify(cachedEntry.data), { status: 200, headers: {'Content-Type': 'application/json'} });
            }
          }

          const parsedBody = originalJsonParse(options.body); 
          let modifiedJSON = parsedBody;

          if (CONFIG.enablePiiRedaction) {
             modifiedJSON = redactObject(modifiedJSON, reqId);
          }
          if (CONFIG.enablePromptCompression || CONFIG.enableJsonShorthand) {
             modifiedJSON = applyULICCompression(modifiedJSON);
          }

          options.body = JSON.stringify(modifiedJSON);
          bodyWasModified = true;

          console.log(`\n[SafeLM SDK] 🚀 Processed Outbound API Call to: ${urlString} (PII/Compression Applied)`);
        }
      } catch (e) {
        console.debug(`[SafeLM SDK] Body parsing skipped: ${e.message}`);
      }

      // Send actual request
      const response = await originalFetch.apply(this, [url, options]);

      // Cache the response unconditionally before un-redacting so future identical requests skip the roundtrip
      try {
        if (CONFIG.enableCaching && payloadHash && response.ok) {
           const cacheClone = response.clone();
           const jsonCache = await cacheClone.json();
           llmResponseCache.set(payloadHash, {
              data: jsonCache,
              expiresAt: Date.now() + CACHE_TTL_MS
           });
        }
      } catch(e) {}

      // PII Restoration 
      if (bodyWasModified && CONFIG.enablePiiRedaction && response.ok) {
        try {
          const clonedResponse = response.clone();
          const jsonResponse = await clonedResponse.json();
          const restoredJSON = restoreObject(jsonResponse, reqId);

          delete vaultStore[reqId];
          console.log(`[SafeLM SDK] 🔓 PII restored to response payload!\n`);

          return new Response(JSON.stringify(restoredJSON), {
              status: response.status,
              statusText: response.statusText,
              headers: response.headers
          });
        } catch (e) {
          console.debug(`[SafeLM SDK] Response restoration skipped: ${e.message}`);
        }
      }

      delete vaultStore[reqId];
      return response;
    };
    console.log('[SafeLM SDK] Global \`fetch\` hooked successfully.');
  }
}

// --- SDK Initialization ---
async function verifySubscription(customerApiKey) {
  return customerApiKey && customerApiKey.startsWith('SafeLM_');
}

async function init(customerApiKey, configPath = './SafeLM.config.json') {
  if (isInitialized) return;

  console.log(`[SafeLM SDK] Initializing...`);

  try {
    const fullPath = path.resolve(process.cwd(), configPath);
    const rawData = fs.readFileSync(fullPath, 'utf-8');
    const userConfig = originalJsonParse(rawData);
    CONFIG = { ...CONFIG, ...userConfig };
    console.log(`[SafeLM SDK] Config loaded (${CONFIG.targetDomains.length} target domains tracked).`);
  } catch (err) {
    console.error(`[SafeLM SDK] ❌ Critical: Could not read config file at ${configPath}`);
    throw new Error('SafeLM Config Missing: Cannot start SDK without a valid configuration file.');
  }

  const isValid = await verifySubscription(customerApiKey);
  if (!isValid) {
    console.error(`[SafeLM SDK] ❌ Critical: Invalid or Expired SafeLM API Key.`);
    throw new Error('SafeLM Authentication Error: Invalid API Key provided.');
  }

  isInitialized = true;
  console.log(`[SafeLM SDK] ✅ Subscription verified!`);
  
  applyOutboundMonkeyPatch();
  applyWAFMonkeyPatch();

  setInterval(async () => {
    const stillValid = await verifySubscription(customerApiKey);
    if (!stillValid) {
      console.error(`[SafeLM SDK] ❌ Background Check Failed. Subscription expired! Disabling SafeLM.`);
      isInitialized = false; 
    }
  }, 1000 * 60 * 60 * 1);

  // Phase 1: Crash Protection Wrapper
  if (CONFIG.enableCrashProtection) {
    process.on('uncaughtException', (err) => {
      telemetryStats.threatsBlocked++;
      console.error(`[SafeLM SDK] 🛡️ Blocked fatal app crash (uncaughtException):`, err.message);
    });
    process.on('unhandledRejection', (reason) => {
      telemetryStats.threatsBlocked++;
      console.error(`[SafeLM SDK] 🛡️ Blocked fatal app crash (unhandledRejection):`, reason);
    });
    console.log('[SafeLM SDK] 🛡️ Global Crash Protection Activated.');
  }

  // Phase 1: Telemetry Background Sync
  if (CONFIG.telemetryEndpoint) {
    setInterval(async () => {
      if (telemetryStats.tokensSaved > 0 || telemetryStats.threatsBlocked > 0 || telemetryStats.cachesHit > 0) {
        try {
          if (originalFetch) {
             const payload = JSON.stringify(telemetryStats);
             await originalFetch(CONFIG.telemetryEndpoint, { method: 'POST', body: payload });
             telemetryStats.tokensSaved = 0;
             telemetryStats.threatsBlocked = 0;
             telemetryStats.cachesHit = 0;
          }
        } catch (e) { /* fail silently for background telemetry */ }
      }
    }, 60 * 1000); 
  }
}

module.exports = { init };
