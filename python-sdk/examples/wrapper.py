# wrapper.py
# SafeLM Python Example Wrapper

import os
import sys

# 1. Import the SafeLM SDK
import safelm

# 2. Get your SafeLM License Key
SAFELM_API_KEY = os.environ.get("SAFELM_API_KEY", "safelm_sdk_demo_key")

def run_application():
    print("[App] Initializing SafeLM Wrapper...")
    
    try:
        # 3. Initialize the SDK Wrapper to catch crashes and apply protections
        # SafeLM seamlessly hooks into sys.excepthook, urllib.request, etc.
        safelm.init(SAFELM_API_KEY, config_path="../safelm.config.json")
        print("[App] SafeLM initialized! Application runs under a shield.")
        
        # 4. Main Application Loop
        # Insert your Flask, Django, or FastAPI runner here.
        # Everything fetched via urllib or parsed via JSON is filtered transparently.
        print("[App] Proceeding with main execution logic.")
        
        # For example, simulating a server:
        # app.run(port=8080)
        
    except Exception as e:
        print(f"[App] initialization failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    run_application()
