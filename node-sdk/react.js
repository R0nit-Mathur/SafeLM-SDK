/**
 * SafeLM React Context Stub
 * 
 * Demonstrates how SafeLM Huffman Dictionary can theoretically sync with the frontend 
 * WITHOUT exposing the compression engine algorithms to reverse engineers.
 * 
 * Usage:
 * <SafeLMProvider apiKey="front_end_demo_key"> <App /> </SafeLMProvider>
 */

import React, { createContext, useContext, useEffect, useState } from 'react';

const SafeLMContext = createContext({ isReady: false, dictionary: null });

export const SafeLMProvider = ({ apiKey, children }) => {
  const [isReady, setIsReady] = useState(false);
  const [dictionary, setDictionary] = useState(null);

  useEffect(() => {
    // 1. Fetch Dynamic Dictionary from SafeLM backend.
    // The dictionary is rotated specific to the 'apiKey' or session to prevent replay attacks.
    async function syncSafeLMDictionary() {
      try {
        const response = await fetch("https://api.safelm.io/v1/client-sync", {
          headers: { "Authorization": `Bearer ${apiKey}` }
        });
        
        if (response.ok) {
           const data = await response.json();
           setDictionary(data.huffmanDict);
           setIsReady(true);
           console.log("[SafeLM Client] 🛡️ Shield synced successfully.");
        }
      } catch (err) {
        console.warn("[SafeLM Client] Dictionary sync failed. Falling back to native uncompressed mode.");
      }
    }
    syncSafeLMDictionary();
  }, [apiKey]);

  // SafeLM hooks globally intercept fetch from the browser context
  // Only applying compression if `dictionary` is loaded, BUT leaving core security logic
  // (like WAF blocks or PII) to the backend API Server.
  // This effectively hides the proprietary regex patterns and SDK logic entirely from the end-user.
  
  return (
    <SafeLMContext.Provider value={{ isReady, dictionary }}>
      {children}
    </SafeLMContext.Provider>
  );
};

export const useSafeLM = () => useContext(SafeLMContext);
