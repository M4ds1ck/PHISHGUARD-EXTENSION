// content.js - v3.0.0 with Privacy Consent & Optimized Detection
(function() {
'use strict';

if (window.phishGuardRunning) {
  console.log("[PhishGuard] Already running on this page");
  return;
}

window.phishGuardRunning = true;
console.log("[PhishGuard] Starting scan engine...");

const browserAPI = browser;

// Verify utils loaded
if (typeof PhishGuardUtils === 'undefined') {
  console.error("[PhishGuard] Utils not loaded! Aborting.");
  return;
}

// ============================================
// CONFIGURATION
// ============================================
let CONFIG = {
  LEGITIMATE_DOMAINS: [
    'google.com', 'youtube.com', 'gmail.com', 'microsoft.com', 'office.com',
    'apple.com', 'icloud.com', 'amazon.com', 'facebook.com', 'meta.com',
    'instagram.com', 'twitter.com', 'x.com', 'linkedin.com', 'reddit.com',
    'github.com', 'gitlab.com', 'stackoverflow.com', 'netflix.com', 'spotify.com',
    'paypal.com', 'stripe.com', 'ebay.com', 'walmart.com', 'target.com',
    'duckduckgo.com', 'bing.com', 'mozilla.org'
  ],
  SUSPICIOUS_KEYWORDS: [
    'verify', 'account', 'secure', 'update', 'confirm', 'login',
    'banking', 'suspended', 'locked', 'urgent', 'expire', 'password'
  ]
};

// ============================================
// DOMAIN CHECKS
// ============================================
function isLegitimateWebsite(hostname) {
  const domain = hostname.toLowerCase();

  // Direct match
  if (CONFIG.LEGITIMATE_DOMAINS.includes(domain)) return true;

  // Check without www
  if (domain.startsWith('www.')) {
    const withoutWww = domain.substring(4);
    if (CONFIG.LEGITIMATE_DOMAINS.includes(withoutWww)) return true;
  }

  // Check if subdomain of legitimate
  for (const legitDomain of CONFIG.LEGITIMATE_DOMAINS) {
    if (domain.endsWith('.' + legitDomain)) return true;
  }

  return false;
}

function extractBaseDomain(hostname) {
  const parts = hostname.split('.');
  return parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
}

// ============================================
// VISUAL WARNINGS
// ============================================
function showHTTPWarning() {
  if (document.getElementById('phishguard-banner')) return;

  const banner = document.createElement('div');
  banner.id = 'phishguard-banner';
  banner.innerHTML = `
    <div style="
      position: fixed; top: 0; left: 0; right: 0;
      background: linear-gradient(135deg, #ff003c 0%, #ff6b00 100%);
      color: white; padding: 12px 20px; text-align: center;
      font-family: system-ui, sans-serif; font-size: 14px;
      font-weight: 600; z-index: 2147483647;
      box-shadow: 0 2px 10px rgba(0,0,0,0.3);
      display: flex; align-items: center; justify-content: center;
    ">
      <span>⚠️ WARNING: This site uses insecure HTTP. Your data may be visible to others.</span>
      <button onclick="this.parentElement.remove()" style="
        background: rgba(255,255,255,0.2); border: 1px solid white;
        color: white; padding: 4px 12px; border-radius: 4px;
        cursor: pointer; margin-left: 15px; font-weight: 600;
        flex-shrink: 0;
      ">Dismiss</button>
    </div>
  `;
  document.body.appendChild(banner);

  // Auto-dismiss after 10 seconds
  setTimeout(() => {
    if (banner.parentElement) banner.remove();
  }, 10000);
}

function showCriticalAlert() {
  const hasPassword = document.querySelector('input[type="password"]');
  if (!hasPassword) return;
  if (document.getElementById('phishguard-critical')) return;

  const alert = document.createElement('div');
  alert.id = 'phishguard-critical';
  alert.innerHTML = `
    <div style="
      position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%);
      background: #1a0000; color: white; padding: 30px 40px;
      border-radius: 12px; box-shadow: 0 10px 40px rgba(255,0,60,0.5);
      z-index: 2147483647; max-width: 500px; text-align: center;
      border: 2px solid #ff003c;
    ">
      <div style="font-size: 48px;">🚨</div>
      <h2 style="margin: 15px 0; color: #ff003c;">CRITICAL SECURITY WARNING</h2>
      <p style="margin: 10px 0; font-size: 16px;">
        This site has <strong>LOGIN FORMS</strong> on <strong>UNENCRYPTED HTTP</strong>.
      </p>
      <p style="margin: 10px 0; color: #ffaaaa; font-weight: 500;">
        ⚠️ DO NOT enter passwords! Your data can be intercepted by attackers.
      </p>
      <button onclick="this.parentElement.parentElement.remove()" style="
        background: #ff003c; border: none; color: white;
        padding: 12px 30px; border-radius: 6px; cursor: pointer;
        font-weight: 700; text-transform: uppercase; margin-top: 15px;
        box-shadow: 0 4px 10px rgba(255,0,60,0.3);
      ">I Understand</button>
    </div>
    <div onclick="this.parentElement.remove()" style="
      position: fixed; top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0,0,0,0.85); z-index: 2147483646;
    "></div>
  `;
  document.body.appendChild(alert);
}

// ============================================
// FORM ANALYSIS
// ============================================
function checkExternalForms() {
  const forms = document.querySelectorAll('form[action]');
  const currentHost = window.location.hostname;
  let externalForms = 0;
  
  forms.forEach(form => {
    try {
      const action = form.getAttribute('action');
      if (action && action.startsWith('http')) {
        const actionHost = new URL(action).hostname;
        if (actionHost.toLowerCase() !== currentHost.toLowerCase()) {
          externalForms++;
        }
      }
    } catch (e) {}
  });
  
  return externalForms;
}

// ============================================
// MAIN SCAN ENGINE
// ============================================
async function scanWebsite() {
  console.log("[PhishGuard] Scanning", window.location.href);
  
  // Skip system pages
  if (window.location.href.startsWith('about:') || 
      window.location.href.startsWith('moz-extension:')) {
    console.log("[PhishGuard] Skipping system page");
    return;
  }

  let score = 0;
  const reasons = [];
  const url = window.location.href;
  const hostname = window.location.hostname;
  const protocol = window.location.protocol;

  // Legitimate site check
  const isLegit = isLegitimateWebsite(hostname);
  
  // HTTP warnings (even for legitimate sites)
  if (protocol === 'http:') {
    showHTTPWarning();
    score += 15;
    reasons.push({
      reason: "Unencrypted HTTP Connection",
      weight: 15,
      detail: "Site doesn't use HTTPS encryption",
      category: 'protocol'
    });

    // Critical alert for password forms on HTTP
    if (document.querySelector('input[type="password"]')) {
      showCriticalAlert();
      score += 50;
      reasons.push({
        reason: "🚨 CRITICAL: Login Form on HTTP",
        weight: 50,
        detail: "Password fields on unencrypted connection",
        category: 'critical_http'
      });
    }
  }

  // External form submission
  const externalForms = checkExternalForms();
  if (externalForms > 0) {
    score += 30;
    reasons.push({
      reason: "Forms Submit to External Domain",
      weight: 30,
      detail: `${externalForms} forms send data to different domains`,
      category: 'external_forms'
    });
  }

  // Only send report if not legitimate OR has security issues
  if (!isLegit || score > 0) {
    const report = {
      score: score,
      reasons: reasons,
      url: url,
      hostname: hostname,
      protocol: protocol,
      legitimate: isLegit,
      timestamp: Date.now()
    };

    console.log("[PhishGuard] Scan complete - Score:", score);
    sendReport(report);
    return report;
  }
  
  console.log("[PhishGuard] Legitimate site with no issues detected");
  return { score: 0, reasons: [], legitimate: true };
}

// ============================================
// REPORT SENDING
// ============================================
function sendReport(report) {
  try {
    browserAPI.runtime.sendMessage({
      action: "reportRisk",
      data: report
    }).catch(error => {
      console.warn("[PhishGuard] Could not send report:", error);
    });
  } catch (e) {
    console.error("[PhishGuard] Error sending report:", e);
  }
}

// ============================================
// MESSAGE LISTENER
// ============================================
browserAPI.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log("[PhishGuard] Message received:", request.action);

  if (request.action === "ping") {
    sendResponse({ status: "alive" });
    return false;
  }

  if (request.action === "manualScan") {
    scanWebsite().then(report => {
      sendResponse({ status: "complete", report: report });
    }).catch(error => {
      sendResponse({ status: "error", error: error.message });
    });
    return true;
  }

  return false;
});

// ============================================
// AUTO-SCAN ON PAGE LOAD
// ============================================
function init() {
  console.log("[PhishGuard] Initializing scan...");
  
  // Wait for body to exist
  if (!document.body) {
    document.addEventListener('DOMContentLoaded', init);
    return;
  }
  
  // Delay scan to allow page to load
  setTimeout(scanWebsite, 1000);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}

console.log("[PhishGuard] ✅ Ready for scanning");
})();