// warning.js - v3.0.0 with Confirmation Dialog & Privacy Notice
console.log("[Warning Page] Loading...");
const browserAPI = browser;
console.log("[Warning Page] Browser:", browserAPI ? "Firefox" : "Unknown");

let blockedUrl = '';
let score = 0;
let bypassAttempted = false;
let consentGranted = false;

// ============================================
// INITIALIZATION
// ============================================
document.addEventListener('DOMContentLoaded', function() {
  console.log("[Warning Page] DOM ready");
  
  try {
    // Get URL parameters
    const params = new URLSearchParams(window.location.search);
    blockedUrl = params.get('url') || '';
    score = parseInt(params.get('score')) || 0;
    const reasonsParam = params.get('reasons') || '[]';

    console.log("[Warning Page] Blocked URL:", blockedUrl);
    console.log("[Warning Page] Score:", score);

    // Validate URL
    if (!blockedUrl || !isValidURL(blockedUrl)) {
      console.error("[Warning Page] Invalid blocked URL");
      document.getElementById('blockedUrl').textContent = "Invalid URL";
      disableContinueButton("Invalid URL");
      return;
    }

    // Display blocked URL (sanitized)
    displayBlockedURL(blockedUrl);

    // Animate score and set threat level
    animateScore(score);
    setThreatLevel(score);

    // Parse and display reasons
    try {
      const reasons = JSON.parse(decodeURIComponent(reasonsParam));
      console.log("[Warning Page] Reasons:", reasons);
      displayReasons(reasons);
    } catch (e) {
      console.error("[Warning Page] Parse error:", e);
      displayReasons([]);
    }

    // Setup buttons
    setupButtons();

    // Check consent status
    checkConsentStatus();
    
  } catch (error) {
    console.error("[Warning Page] Initialization error:", error);
    showError("Failed to load warning page: " + error.message);
  }
});

// ============================================
// URL VALIDATION
// ============================================
function isValidURL(string) {
  try {
    const url = new URL(string);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch (_) {
    return false;
  }
}

// ============================================
// UI DISPLAY FUNCTIONS
// ============================================
function displayBlockedURL(url) {
  const urlEl = document.getElementById('blockedUrl');
  if (!urlEl) return;
  
  try {
    const urlObj = new URL(url);
    // Display only hostname for security
    urlEl.textContent = urlObj.hostname;
    urlEl.title = url; // Full URL in tooltip
  } catch (e) {
    urlEl.textContent = "Invalid URL";
  }
}

function setThreatLevel(score) {
  const levelEl = document.getElementById('threatLevel');
  if (!levelEl) return;
  
  if (score >= 75) {
    levelEl.textContent = "CRITICAL RISK";
    levelEl.style.color = "#ff003c";
  } else if (score >= 50) {
    levelEl.textContent = "HIGH RISK";
    levelEl.style.color = "#ff3b3b";
  } else if (score >= 25) {
    levelEl.textContent = "MEDIUM RISK";
    levelEl.style.color = "#ff6b00";
  } else {
    levelEl.textContent = "LOW RISK";
    levelEl.style.color = "#ffb300";
  }
}

function animateScore(target) {
  const scoreEl = document.getElementById('threatScore');
  if (!scoreEl) return;
  
  let current = 0;
  const step = Math.ceil(target / 75);
  const timer = setInterval(() => {
    current += step;
    if (current >= target) {
      current = target;
      clearInterval(timer);
    }
    scoreEl.textContent = current;
  }, 20);
}

function displayReasons(reasons) {
  const list = document.getElementById('reasonsList');
  if (!list) return;
  
  list.innerHTML = '';

  if (!reasons || reasons.length === 0) {
    list.innerHTML = `
      <div class="threat-item">
        <div class="threat-name">Suspicious activity detected</div>
        <div class="threat-badge badge-medium">MED</div>
      </div>
    `;
    return;
  }

  console.log("[Warning Page] Displaying", reasons.length, "reasons");

  // Sort by weight (highest first)
  const sortedReasons = [...reasons].sort((a, b) => (b.weight || 0) - (a.weight || 0));

  sortedReasons.forEach(r => {
    const item = document.createElement('div');
    item.className = 'threat-item';

    const weight = r.weight || 0;
    let badgeClass = 'badge-low';
    
    if (weight >= 50) {
      badgeClass = 'badge-critical';
    } else if (weight >= 25) {
      badgeClass = 'badge-high';
    } else if (weight >= 10) {
      badgeClass = 'badge-medium';
    }

    // Sanitize reason text
    const reasonText = escapeHtml(r.reason || 'Unknown threat');
    const detailText = r.detail ? `: ${escapeHtml(r.detail)}` : '';

    item.innerHTML = `
      <div class="threat-name">${reasonText}${detailText}</div>
      <div class="threat-badge ${badgeClass}">
        ${weight >= 50 ? 'CRITICAL' : weight >= 25 ? 'HIGH' : weight >= 10 ? 'MED' : 'LOW'}
      </div>
    `;
    list.appendChild(item);
  });
}

function showError(msg) {
  const reasonsList = document.getElementById('reasonsList');
  if (reasonsList) {
    reasonsList.innerHTML = `<div style="padding:15px; color:#ff6b6b; font-size:14px; background: rgba(255,107,107,0.1); border-radius:8px; margin-top:10px;">${escapeHtml(msg)}</div>`;
  }
}

// ============================================
// CONSENT MANAGEMENT
// ============================================
async function checkConsentStatus() {
  try {
    const response = await browserAPI.runtime.sendMessage({
      action: "getConsentStatus"
    });
    
    if (response) {
      consentGranted = response.apis && response.urlExpansion;
      
      // Update UI based on consent
      const continueBtn = document.getElementById('continueBtn');
      if (continueBtn) {
        if (consentGranted) {
          continueBtn.disabled = false;
          continueBtn.innerHTML = `<span id="continueText">I Understand the Risks (Proceed Anyway)</span>`;
        } else {
          continueBtn.innerHTML = `<span id="continueText">⚠️ Requires Privacy Consent</span>`;
        }
      }
    }
  } catch (error) {
    console.warn("[Warning Page] Consent check failed:", error);
  }
}

// ============================================
// BUTTON HANDLERS (WITH CONFIRMATION)
// ============================================
function setupButtons() {
  console.log("[Warning Page] Setting up buttons");
  
  // Close/Go back button
  const goBackBtn = document.getElementById('goBackBtn');
  if (goBackBtn) {
    goBackBtn.onclick = () => {
      console.log("[Warning Page] Go back clicked");
      window.history.back();
    };
  }

  // Continue button - REQUIRES CONFIRMATION
  const continueBtn = document.getElementById('continueBtn');
  if (continueBtn) {
    continueBtn.onclick = async () => {
      if (bypassAttempted) {
        console.log("[Warning Page] Bypass already attempted");
        return;
      }

      // Show confirmation dialog
      if (!confirmBypass()) {
        return;
      }

      bypassAttempted = true;
      console.log("[Warning Page] Continue clicked - bypassing to:", blockedUrl);

      // Disable button immediately
      continueBtn.disabled = true;
      continueBtn.innerHTML = `<span id="continueText">Setting bypass...</span>`;

      try {
        // Validate URL one more time
        if (!isValidURL(blockedUrl)) {
          throw new Error("Invalid URL");
        }

        // Set bypass in background
        console.log("[Warning Page] Sending bypass message...");
        const response = await browserAPI.runtime.sendMessage({
          action: "setTemporaryBypass",
          url: blockedUrl
        });

        console.log("[Warning Page] Bypass response:", response);

        if (!response || response.error) {
          throw new Error(response ? response.error : "No response from background");
        }

        // Wait briefly for bypass to register
        continueBtn.innerHTML = `<span id="continueText">Redirecting...</span>`;
        await new Promise(resolve => setTimeout(resolve, 300));

        // Redirect to the blocked site
        console.log("[Warning Page] ✅ Redirecting to:", blockedUrl);
        window.location.href = blockedUrl;

      } catch (error) {
        console.error("[Warning Page] Bypass failed:", error);
        
        // Show error to user
        showErrorBanner(`Failed to proceed: ${error.message}`);
        
        // Re-enable button after delay
        setTimeout(() => {
          continueBtn.disabled = false;
          continueBtn.innerHTML = `<span id="continueText">I Understand the Risks (Proceed Anyway)</span>`;
          bypassAttempted = false;
        }, 3000);
      }
    };
  }
}

function confirmBypass() {
  // Create custom confirmation dialog (better UX than native alert)
  const confirmed = confirm(
    "⚠️ SECURITY WARNING\n\n" +
    "You are about to bypass PhishGuard protection and visit a potentially malicious site.\n\n" +
    "Risks include:\n" +
    "• Password theft\n" +
    "• Financial fraud\n" +
    "• Malware infection\n" +
    "• Identity theft\n\n" +
    "Only proceed if you ABSOLUTELY trust this site and understand the risks.\n\n" +
    "Are you sure you want to continue?"
  );
  
  if (!confirmed) {
    console.log("[Warning Page] Bypass cancelled by user");
    return false;
  }
  
  console.log("[Warning Page] User confirmed bypass");
  return true;
}

function disableContinueButton(reason) {
  const continueBtn = document.getElementById('continueBtn');
  if (continueBtn) {
    continueBtn.disabled = true;
    continueBtn.innerHTML = `<span id="continueText">${reason || 'Cannot Proceed'}</span>`;
    continueBtn.style.opacity = '0.6';
    continueBtn.style.cursor = 'not-allowed';
  }
}

function showErrorBanner(msg) {
  const errorMsg = document.createElement('div');
  errorMsg.style.cssText = `
    position: fixed;
    top: 20px;
    left: 50%;
    transform: translateX(-50%);
    background: #ff003c;
    color: white;
    padding: 15px 30px;
    border-radius: 12px;
    z-index: 999999;
    text-align: center;
    box-shadow: 0 10px 40px rgba(255,0,60,0.5);
    font-weight: 600;
    max-width: 90%;
    word-wrap: break-word;
  `;
  errorMsg.textContent = msg;
  document.body.appendChild(errorMsg);

  // Remove error after 4 seconds
  setTimeout(() => errorMsg.remove(), 4000);
}

// ============================================
// UTILITIES
// ============================================
function escapeHtml(text) {
  if (typeof text !== 'string') return String(text);
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// ============================================
// PAGE VISIBILITY TRACKING
// ============================================
document.addEventListener('visibilitychange', function() {
  if (document.hidden) {
    console.log("[Warning Page] Hidden - user switched tabs");
  } else {
    console.log("[Warning Page] Visible again");
  }
});

// Prevent accidental back button during redirect
window.addEventListener('popstate', function(event) {
  if (!bypassAttempted) {
    console.log("[Warning Page] Popstate detected - keeping user on warning page");
    history.pushState(null, document.title, location.href);
  }
});

// Initial history state
history.pushState(null, document.title, location.href);
console.log("[Warning Page] ✅ Loaded with confirmation dialog enabled");