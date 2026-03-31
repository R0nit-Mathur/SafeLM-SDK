/*
  wrapper.js
  SafeLM Node.js Example Wrapper
  
  Usage: Wrap this around your main application logic or Express server.
  The SafeLM SDK handles WAF, Token Compression, and Crash Prevention transparently!
*/

const SafeLM = require('../safelm');
const fs = require('fs');
const path = require('path');

// 1. Define your SafeLM License Key
const SAFELM_API_KEY = process.env.SAFELM_API_KEY || "safelm_sdk_demo_key";

async function runApplication() {
  console.log("[App] Initializing SafeLM Wrapper...");
  
  try {
    // 2. Wrap your application initialization with SafeLM
    // Provide the path to your config file if you have specific domains.
    await SafeLM.init(SAFELM_API_KEY, path.join(__dirname, '../safelm.config.json'));
    console.log("[App] SafeLM acts as an invisible shield for out/inbound traffic!\n");

    // 3. Your MAIN application code goes here!
    // SafeLM will transparently un-redact PII, compress prompts, block crashes, etc.
    
    // Example: Normal code fetching from an LLM. 
    // You don't need to change any logic inside!
    console.log("[App] Proceeding with main tasks...");
    
    // Simulate your SaaS logic:
    // const express = require('express');
    // const app = express();
    // app.listen(3000, () => console.log('SaaS running safely protected by SafeLM'));

  } catch (error) {
    console.error("[App] Application initialization failed: ", error);
    process.exit(1);
  }
}

runApplication();
