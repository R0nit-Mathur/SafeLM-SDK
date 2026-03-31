/**
 * SafeLM Next.js API Wrapper
 * Usage:
 * export default withSafeLM(async function handler(req, res) { ... });
 */

const SafeLM = require('./safelm');
const path = require('path');

// Auto-initialize SafeLM for Next.js processes
const SAFELM_API_KEY = process.env.SAFELM_API_KEY || "safelm_sdk_demo_key";
const CONFIG_PATH = process.env.SAFELM_CONFIG_PATH || path.join(process.cwd(), 'safelm.config.json');

// Initialize asynchronously (non-blocking for module load)
SafeLM.init(SAFELM_API_KEY, CONFIG_PATH).catch(e => {
  console.warn(`[SafeLM Next.js] Failed to initialize: ${e.message}`);
});

function scanNextJsRequest(req) {
  // If the query parameters or URL contain malicious payloads
  // the hooked JSON.parse in SafeLM covers body, 
  // but we manually scan URL queries here for extra safety.
  if (!req.url) return;
  try {
     const fakeObj = { url_query: req.url };
     // Pass through the same WAF monkey-patch by force-parsing to trigger hook
     // (or we can just let SafeLM's JSON interceptor handle the JSON body)
     JSON.parse(JSON.stringify(fakeObj));
  } catch(e) {
     if (e.message.includes('SafeLM WAF')) throw e;
  }
}

function withSafeLM(handler) {
  return async (req, res) => {
    try {
      scanNextJsRequest(req);
      return await handler(req, res);
    } catch (error) {
      if (error.message && error.message.includes('SafeLM WAF')) {
        return res.status(403).json({ error: 'SafeLM Security: Threat Detected.' });
      }
      // If Crash Protection is on, we prevent 500s from tearing down the lambda thread
      console.error("[SafeLM Next.js Framework] Caught unhandled exception:", error);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
  };
}

module.exports = { withSafeLM };
