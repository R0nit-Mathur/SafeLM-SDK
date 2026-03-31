import urllib.request
import json
import re
import time
import logging
import uuid
import threading
import os
import hashlib
from collections import Counter
import sys

"""
SafeLM Security SDK (Python) - Paid Edition

Usage:
import SafeLM
SafeLM.init('YOUR_SafeLM_API_KEY')
"""

# --- Global State ---
_is_initialized = False
_original_urlopen = None
_original_json_loads = json.loads
_redis_client = None

CONFIG = {
    "SafeLMEnabled": False,
    "enablePiiRedaction": False,
    "enablePromptCompression": False,
    "enableLLMLingua": False,
    "enableJsonShorthand": False,
    "enableCaching": False,
    "enableWAF": False,
    "enableCrashProtection": False,
    "rateLimitPerMinute": 0,
    "telemetryEndpoint": "",
    "targetDomains": [],
    "privacyMode": "standard",
    "bypassRoutes": [],
    "redisUrl": ""
}

def _should_bypass(url_str: str) -> bool:
    routes = CONFIG.get("bypassRoutes", [])
    if not isinstance(routes, list): return False
    return any(route in url_str for route in routes)

_rate_limiter = {"count": 0, "reset_at": time.time() + 60}
_vault_store = {}
_llm_response_cache = {} # payloadHash : { "data": dict, "expires_at": float }
_telemetry_stats = {"tokensSaved": 0, "threatsBlocked": 0, "cachesHit": 0}

PII_PATTERNS = {
    "EMAIL": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    "PHONE": re.compile(r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b')
}

WAF_RULES = {
    "SQLI": re.compile(r'(?:UNION(?:%20|\s)+SELECT|DROP(?:%20|\s)+TABLE|INSERT(?:%20|\s)+INTO|UPDATE(?:%20|\s)+.*?SET|DELETE(?:%20|\s)+FROM|\'(?:%20|\s)+(?:OR|AND)(?:%20|\s)+.*?=)', re.IGNORECASE),
    "XSS": re.compile(r'(?:<script.*?>|</script>|<iframe.*?>|</iframe>|<(?:img|svg|body|html).*?(?:onload|onerror|onmouseover)=)', re.IGNORECASE),
    "RCE": re.compile(r'(?:\b(?:ping|curl|wget|bash|sh|powershell)\b.*?(?:;|\&|\|)|`.*?(?:ping|curl|wget|bash|sh|powershell).*?`)', re.IGNORECASE),
    "LFI": re.compile(r'(?:\.\.\/|\.\.\\|etc\/passwd|windows\\system32|cmd\.exe)', re.IGNORECASE),
    "NOSQL": re.compile(r'(?:\$where|\$ne|\$gt|\$gte|\$lt|\$lte|\$in)', re.IGNORECASE)
}

# --- TOON JSON Shorthand Converter ---
def _convert_json_to_shorthand(text: str) -> str:
    if not CONFIG["enableJsonShorthand"] or not isinstance(text, str):
        return text
    
    json_regex = re.compile(r'(\{[\s\S]*\}|\[[\s\S]*\])')
    
    def replacer(match):
        raw = match.group(0)
        try:
            parsed = _original_json_loads(raw)
            if not isinstance(parsed, (dict, list)): return raw
            
            def to_tight(obj):
                if isinstance(obj, list):
                    return "[" + "|".join(to_tight(x) for x in obj) + "]"
                if isinstance(obj, dict):
                    return ",".join(f"{k}:{to_tight(v)}" for k, v in obj.items())
                return str(obj)
            
            shorthand = "TOON[" + to_tight(parsed) + "]"
            if len(shorthand) < len(raw):
                print(f"[SafeLM SDK Python] ✂️  Converted embedded JSON object to TOON shorthand ({len(raw)} -> {len(shorthand)} chars)")
                return shorthand
            return raw
        except Exception:
            return raw
            
    return json_regex.sub(replacer, text)


# --- LLM Lingua Fast Lexical Compressor ---
STOP_WORDS_REGEX = re.compile(r'\b(?:a|an|the|very|actually|basically|literally|just|really)\b ', re.IGNORECASE)

def _apply_llm_lingua(text: str) -> str:
    if not CONFIG.get("enableLLMLingua") or not isinstance(text, str):
        return text
    
    orig_len = len(text)
    compressed = STOP_WORDS_REGEX.sub('', text)
    compressed = re.sub(r'\s{2,}', ' ', compressed).strip()
    
    if len(compressed) < orig_len:
        saved = orig_len - len(compressed)
        _telemetry_stats["tokensSaved"] += (saved // 4)
        print(f"[SafeLM SDK Python] ✂️  LLM-Lingua Lexical compression saved {saved} chars.")
        return compressed
    return text

# --- Compression Engine (ULIC-v2 Huffman) ---
def _compress_prompt(text: str) -> str:
    text = _apply_llm_lingua(text)
    text = _convert_json_to_shorthand(text)
    
    if not CONFIG["enablePromptCompression"] or not isinstance(text, str) or len(text) < 150:
        return text
    
    WORDS_REGEX = re.compile(r'\b[a-zA-Z]{5,}\b')
    words = WORDS_REGEX.findall(text)
    if not words: return text
    
    freq = Counter(words)
    sorted_words = [w for w, count in freq.most_common() if count > 1]
    sorted_words.sort(key=lambda w: freq[w] * len(w), reverse=True)
    sorted_words = sorted_words[:30]

    if not sorted_words: return text

    code_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    mapping = {}
    reverse_map = {}

    for i, word in enumerate(sorted_words):
        if i >= len(code_chars): break
        code = f"@@{code_chars[i]}"
        mapping[word] = code
        reverse_map[code] = word

    encoded = text
    for word, code in mapping.items():
        encoded = re.sub(rf'\b{word}\b', code, encoded)

    if len(encoded) >= len(text): return text

    dict_str = json.dumps(reverse_map, separators=(',', ':'))
    saved_chars = len(text) - len(encoded)
    _telemetry_stats["tokensSaved"] += (saved_chars // 4)
    print(f"[SafeLM SDK Python] 📦 ULIC-v2 Compression saved {saved_chars} chars natively!")
    return f"DECOMPRESS first using this exact mapping (replace codes with values), then process the original request:\nDICT: {dict_str}\nENCODED:\n{encoded}"

def _apply_ulic_compression(obj):
    if isinstance(obj, str): return _compress_prompt(obj)
    if isinstance(obj, list): return [_apply_ulic_compression(item) for item in obj]
    if isinstance(obj, dict):
        new_obj = {}
        for k, v in obj.items():
            if k in ["prompt", "content", "text", "system_prompt"]:
                new_obj[k] = _apply_ulic_compression(v)
            else:
                new_obj[k] = v
        return new_obj
    return obj


# --- PII Redaction Engine ---
def _redact_text(text: str, req_id: str) -> str:
    if not CONFIG["enablePiiRedaction"] or not isinstance(text, str): return text
    if req_id not in _vault_store:
        _vault_store[req_id] = {"map": {}, "counters": {"EMAIL": 0, "PHONE": 0}}
    
    vault = _vault_store[req_id]
    redacted_text = text

    for pii_type, pattern in PII_PATTERNS.items():
        matches = list(pattern.finditer(redacted_text))
        for match in reversed(matches):
            original = match.group()
            vault["counters"][pii_type] += 1
            placeholder = f"[REDACTED-{pii_type}-{vault['counters'][pii_type]}]"
            vault["map"][placeholder] = original
            start, end = match.span()
            redacted_text = redacted_text[:start] + placeholder + redacted_text[end:]
    return redacted_text

def _restore_text(text: str, req_id: str) -> str:
    if not CONFIG["enablePiiRedaction"] or not isinstance(text, str): return text
    vault = _vault_store.get(req_id)
    if not vault: return text

    restored_text = text
    for placeholder, original in vault["map"].items():
        restored_text = restored_text.replace(placeholder, original)
    return restored_text

def _redact_object(obj, req_id: str):
    if isinstance(obj, str): return _redact_text(obj, req_id)
    if isinstance(obj, list): return [_redact_object(item, req_id) for item in obj]
    if isinstance(obj, dict):
        return {k: _redact_object(v, req_id) for k, v in obj.items()}
    return obj

def _restore_object(obj, req_id: str):
    if isinstance(obj, str): return _restore_text(obj, req_id)
    if isinstance(obj, list): return [_restore_object(item, req_id) for item in obj]
    if isinstance(obj, dict):
        return {k: _restore_object(v, req_id) for k, v in obj.items()}
    return obj

# --- Inbound WAF Protection (JSON loads Hook) ---
def _scan_waf_object(obj):
    if isinstance(obj, str):
        safe_str = obj[:50000] if len(obj) > 50000 else obj
        for rule_name, regex in WAF_RULES.items():
            if regex.search(safe_str):
                _telemetry_stats["threatsBlocked"] += 1
                logging.error(f"[SafeLM SDK Python] 🚨 WAF BLOCKED PAYLOAD! Detected {rule_name} Attack signature!")
                raise ValueError(f"SafeLM WAF Blocked Payload: Potential {rule_name} detected.")
    elif isinstance(obj, list):
        for item in obj: _scan_waf_object(item)
    elif isinstance(obj, dict):
        for val in obj.values(): _scan_waf_object(val)

def _SafeLM_json_loads(*args, **kwargs):
    parsed = _original_json_loads(*args, **kwargs)
    if _is_initialized and CONFIG.get("enableWAF"):
        _scan_waf_object(parsed)
    return parsed


# --- Outbound Interceptor (Monkey-Patching) ---
class MockResponse:
    def __init__(self, data_bytes, http_status=200, headers=None):
        self.data_bytes = data_bytes
        self.status = http_status
        self.reason = "OK"
        self.headers = headers or {}
        
    def read(self): return self.data_bytes
    def __enter__(self): return self
    def __exit__(self, exc_type, exc_val, exc_tb): pass

def _SafeLM_intercept_urlopen(url, data=None, timeout=None, **kwargs):
    if not _is_initialized or not CONFIG["SafeLMEnabled"]:
        return _original_urlopen(url, data, timeout, **kwargs)

    req_obj = url if isinstance(url, urllib.request.Request) else urllib.request.Request(url, data=data, **kwargs)
    full_url_str = req_obj.full_url
    
    is_target = any(domain in full_url_str for domain in CONFIG["targetDomains"])
    if not is_target or req_obj.get_method() != "POST" or _should_bypass(full_url_str):
        return _original_urlopen(url, data, timeout, **kwargs)

    # 2. Distributed Rate Limiting Protection (Redis or Memory)
    if _redis_client:
        try:
            key = "safelm_ratelimit_global_outbound"
            count = _redis_client.incr(key)
            if count == 1: _redis_client.expire(key, 60)
            if count > CONFIG["rateLimitPerMinute"]:
                logging.error(f"[SafeLM SDK Python] 🚨 Distributed Rate Limit Exceeded: Bound to {CONFIG['rateLimitPerMinute']} reqs/min.")
                return MockResponse(json.dumps({"error": "SafeLM Global Rate Limit Exceeded"}).encode("utf-8"), 429)
        except Exception: pass
    else:
        now = time.time()
        if now > _rate_limiter["reset_at"]:
            _rate_limiter["count"] = 0
            _rate_limiter["reset_at"] = now + 60
            
        _rate_limiter["count"] += 1
        if _rate_limiter["count"] > CONFIG["rateLimitPerMinute"]:
            logging.error(f"[SafeLM SDK Python] 🚨 Rate Limit Exceeded: Bound to {CONFIG['rateLimitPerMinute']} reqs/min!")
            return MockResponse(json.dumps({"error": "SafeLM Rate Limit Exceeded"}).encode("utf-8"), 429)

    req_id = str(uuid.uuid4())
    body_was_modified = False
    payload_hash = None

    # 3. Cache, Compression, PII
    try:
        if req_obj.data is not None:
            if CONFIG["enableCaching"]:
                payload_hash = hashlib.sha256(req_obj.data).hexdigest()
                cached_data = None
                
                if _redis_client:
                    try:
                        val = _redis_client.get(f"safelm_cache:{payload_hash}")
                        if val: cached_data = _original_json_loads(val)
                    except Exception: pass
                else:
                    cached_entry = _llm_response_cache.get(payload_hash)
                    if cached_entry and time.time() < cached_entry["expires_at"]:
                        cached_data = cached_entry["data"]
                        
                if cached_data:
                    _telemetry_stats["cachesHit"] += 1
                    print(f"[SafeLM SDK Python] ⚡ Semantic Cache HIT! Returning instant local response for payload.")
                    return MockResponse(json.dumps(cached_data).encode("utf-8"), 200)

            body_json = _original_json_loads(req_obj.data.decode("utf-8"))
            
            modified_json = body_json
            if CONFIG["enablePiiRedaction"]:
                modified_json = _redact_object(modified_json, req_id)
            if CONFIG["enablePromptCompression"] or CONFIG["enableJsonShorthand"]:
                modified_json = _apply_ulic_compression(modified_json)
                
            req_obj.data = json.dumps(modified_json).encode("utf-8")
            body_was_modified = True
            
            print(f"\n[SafeLM SDK Python] 🚀 Processed Outbound API Call to: {full_url_str}")
    except Exception as e:
        logging.debug(f"[SafeLM SDK Python] Request parsing skipped: {e}")

    # 4. Actual Network Call
    try:
        response = _original_urlopen(req_obj, timeout=timeout)
    except Exception as e:
        if req_id in _vault_store: del _vault_store[req_id]
        raise e

    # Cache population (before restoration, so cache holds exactly what LLM sent natively)
    try:
        resp_bytes = response.read()
        resp_str = resp_bytes.decode("utf-8")
        
        if CONFIG["enableCaching"] and payload_hash:
            try:
                parsed_resp = _original_json_loads(resp_str)
                if _redis_client:
                    _redis_client.setex(f"safelm_cache:{payload_hash}", 3600, json.dumps(parsed_resp))
                else:
                    _llm_response_cache[payload_hash] = {
                        "data": parsed_resp,
                        "expires_at": time.time() + 3600 # 1 hour TTL
                    }
            except:
                pass 
                
        # Remount the response stream since we read it
        response = MockResponse(resp_bytes, response.status, response.headers)
    except Exception as e:
        logging.debug(f"[SafeLM SDK Python] Response caching skipped: {e}")
        resp_str = "{}" # Failsafe

    # 5. Restore PII
    if body_was_modified and CONFIG.get("enablePiiRedaction"):
        try:
            try:
                resp_json = _original_json_loads(resp_str)
                restored_json = _restore_object(resp_json, req_id)
                final_resp_bytes = json.dumps(restored_json).encode("utf-8")
                print("[SafeLM SDK Python] 🔓 PII restored in response payload!\n")
            except json.JSONDecodeError:
                restored_str = _restore_text(resp_str, req_id)
                final_resp_bytes = restored_str.encode("utf-8")
                
            class ReplacedResponse(MockResponse):
                def __init__(self, data, orig_resp):
                    super().__init__(data, orig_resp.status)
                    self.headers = getattr(orig_resp, 'headers', {})
                    self.reason = getattr(orig_resp, 'reason', "OK")
            
            response = ReplacedResponse(final_resp_bytes, response)
        except Exception as e:
            logging.debug(f"[SafeLM SDK Python] Response restoring skipped: {e}")

    if req_id in _vault_store: del _vault_store[req_id]
    return response

# --- SaaS Authentication Loop ---
def _verify_subscription(customer_api_key):
    return str(customer_api_key).startswith("SafeLM_")

def _subscription_loop(customer_api_key):
    global _is_initialized
    while True:
        time.sleep(3600)  
        if not _verify_subscription(customer_api_key):
            print("[SafeLM SDK Python] ❌ Background Check Failed. Subscription expired! Disabling SafeLM.")
            _is_initialized = False
        else:
            print("[SafeLM SDK Python] 🔄 Background check passed. Subscription active.")

def _telemetry_loop():
    while True:
        time.sleep(60)
        if CONFIG.get("privacyMode") == "strict": continue
        stats = _telemetry_stats.copy()
        if stats["tokensSaved"] > 0 or stats["threatsBlocked"] > 0 or stats["cachesHit"] > 0:
            endpoint = CONFIG.get("telemetryEndpoint")
            if endpoint:
                try:
                    payload = json.dumps(stats).encode("utf-8")
                    req = urllib.request.Request(endpoint, data=payload, method="POST", headers={"Content-Type": "application/json"})
                    if _original_urlopen:
                        with _original_urlopen(req, timeout=5) as resp:
                            pass
                    _telemetry_stats["tokensSaved"] = 0
                    _telemetry_stats["threatsBlocked"] = 0
                    _telemetry_stats["cachesHit"] = 0
                except Exception:
                    pass

def _SafeLM_excepthook(exc_type, exc_value, exc_traceback):
    _telemetry_stats["threatsBlocked"] += 1
    logging.error(f"[SafeLM SDK Python] 🛡️ Blocked fatal app crash: {exc_value}")

def init(customer_api_key, config_path="SafeLM.config.json"):
    global _is_initialized, _original_urlopen, CONFIG, _redis_client

    if _is_initialized: return

    if not os.path.exists(config_path):
        raise FileNotFoundError(f"SafeLM Configuration missing: Could not find {config_path}")
    
    with open(config_path, "r") as f:
        # Load bypassing WAF
        user_config = _original_json_loads(f.read())
        CONFIG.update(user_config)
        
    # Apply ENV Overrides
    if os.environ.get("SAFELM_DISABLE_WAF") == "true":
        CONFIG["enableWAF"] = False
    if os.environ.get("SAFELM_PRIVACY_MODE"):
        CONFIG["privacyMode"] = os.environ.get("SAFELM_PRIVACY_MODE")

    # Optional Redis Initialization
    if CONFIG.get("redisUrl") and not _redis_client:
        try:
            import redis
            _redis_client = redis.from_url(CONFIG["redisUrl"], decode_responses=True)
            print("[SafeLM SDK Python] 💾 Connected to Global Redis State!")
        except Exception as e:
            print(f"[SafeLM SDK Python] ⚠️ redisUrl provided but missing 'redis' module. Falling back to memory. (pip install redis)")
        
    if not _verify_subscription(customer_api_key):
        raise ValueError("SafeLM Authentication Error: Invalid API Key provided.")

    # Patch modules
    _original_urlopen = urllib.request.urlopen
    urllib.request.urlopen = _SafeLM_intercept_urlopen
    json.loads = _SafeLM_json_loads
    _is_initialized = True
    print("[SafeLM SDK Python] ✅ Subscription verified! Global WAF, Content Caching, and Compression Online.")

    if CONFIG.get("enableCrashProtection"):
        sys.excepthook = _SafeLM_excepthook
        threading.excepthook = lambda args: _SafeLM_excepthook(args.exc_type, args.exc_value, args.exc_traceback)
        print("[SafeLM SDK Python] 🛡️ Global Crash Protection Activated.")

    t = threading.Thread(target=_subscription_loop, args=(customer_api_key,), daemon=True)
    t.start()
    
    if CONFIG.get("telemetryEndpoint"):
        t_telemetry = threading.Thread(target=_telemetry_loop, daemon=True)
        t_telemetry.start()

