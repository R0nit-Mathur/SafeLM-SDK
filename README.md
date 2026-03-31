# SafeLM SDK

**SafeLM** is a zero-dependency, plug-and-play architectural security wrapper and token optimization SDK for AI-integrated applications. It acts as an invisible shield for both your inbound front-end traffic and outbound generative AI requests.

## Features

- **Global WAF Protection**: Instantly blocks massive SQL injection, XSS, Command Injection (RCE), LFI, NoSQL Injection, and ReDoS attacks. 
- **Lossless Token Compression (ULIC-v2 & Lingua)**: Transparently strips connecting filler words and applies native Huffman sequence combinations natively before reaching your LLM.
- **Semantic Prompt Caching**: Captures identical semantic prompts to provide instantaneous local 0-token answers. 
- **Crash Protection Wrapper**: Protects your core SaaS from fatal parsing payload exceptions. Handled transparently by SafeLM.
- **Ready for Dashboard (Phase 3)**: Securely ships authenticated internal telemetry (Tokens Saved, Threats Blocked) directly to the SafeLM performance dashboard via background non-blocking threads.

## Architecture & Analogy: Deploying in a Video Calling SaaS

Consider a large-scale WebRTC video calling application like Zoom or Google Meet that uses an LLM to generate live meeting summaries or sentiment analysis from the audio transcript. 

1. **The Signaling Layer (WebSockets & JSON)**  
   When users join a room, they send chat messages and metadata via JSON. SafeLM sits natively on `JSON.parse`. If a malicious user attempts to send an XSS payload inside the chat box or a NoSQL injection in the room ID, the SafeLM WAF intercepts the inbound parsing event and stops the attack before the room logic even executes it.

2. **The Binary Bypass (Optimization)**  
   Video and Audio are streamed over binary tracks (UDP packets or chunked ArrayBuffers). SafeLM is intelligently designed to bypass binary execution streams natively. It adds zero latency to live video processing.

3. **The LLM Aggregation Layer (Outbound Analysis)**  
   When the meeting ends, the server sends a massive 50,000-word chat array to the LLM for summarization. The SafeLM outbound interceptor catches the `fetch` payload, recursively strips filler words, redacts email addresses (PII), applies ULIC-v2 compression, and caches identical prompts. Tokens are saved, PII is protected, and the mock server instantly receives the restored summary.

4. **Crash Fallback (Resiliency)**  
   If the Python transcription microservice throws an unhandled AsyncIO exception, SafeLM's Crash Hooks capture the failure and prevent the entire container from going offline mid-meeting.

## Repository Structure

- `/node-sdk`: Full integration for Node.js (Express, Fastify, Serverless)
- `/python-sdk`: Full integration for Python 3 (Flask, FastAPI, Django, ASGI)
- `/tests`: Edge-Case auditing suites ensuring security logic validation.

## Usage Example

### Next.js API Example

```javascript
import { withSafeLM } from '../node-sdk/nextjs';

async function handler(req, res) {
    // Your LLM inference logic goes here.
    // SafeLM is securely intercepting parameters, queries, and outbound fetch calls transparently!
    res.status(200).json({ status: "Meeting processing securely." });
}

export default withSafeLM(handler);
```

### Python SDK Example

```python
import safelm
import os

safelm.init(os.environ["SAFELM_API_KEY"], config_path="../safelm.config.json")

# Proceed with Flask/FastAPI runner safely.
```

## Phase 3 Readiness

SafeLM SDK automatically authorizes and transmits metrics (`tokensSaved`, `threatsBlocked`, `cachesHit`) seamlessly to `https://api.safelm.io/v1/telemetry` via a non-blocking background thread. The integration expects standard Phase 3 OAuth processing linked to your provided SafeLM API key.
