// warning.js - DIRECT BYPASS VERSION (No Confirmation Dialogs)
console.log("Warning page loading...");

const browserAPI = browser;
console.log("Browser: Firefox");

let blockedUrl = '';
let score = 0;
let bypassAttempted = false;

// ============================================
// INITIALIZATION
// ============================================

document.addEventListener('DOMContentLoaded', function() {
    console.log("Warning page ready");

    try {
        // Get URL parameters
        const params = new URLSearchParams(window.location.search);
        blockedUrl = params.get('url') || '';
        score = parseInt(params.get('score')) || 0;
        const reasonsParam = params.get('reasons') || '[]';

        console.log("Blocked URL:", blockedUrl);
        console.log("Score:", score);

        // Validate URL
        if (!blockedUrl || !isValidURL(blockedUrl)) {
            console.error("Invalid blocked URL");
            document.getElementById('blockedUrl').textContent = "Invalid URL";
            disableContinueButton();
            return;
        }

        // Create ambient effects
        createBubbles();

        // Display blocked URL (sanitized)
        displayBlockedURL(blockedUrl);

        // Animate score
        animateScore(score);

        // Parse and display reasons
        try {
            const reasons = JSON.parse(decodeURIComponent(reasonsParam));
            console.log("Reasons:", reasons);
            displayReasons(reasons);
        } catch (e) {
            console.error("Parse error:", e);
            displayReasons([]);
        }

        // Setup buttons
        setupButtons();

    } catch (error) {
        console.error("Initialization error:", error);
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
                <div class="threat-badge">WARN</div>
            </div>
        `;
        return;
    }

    console.log("Displaying", reasons.length, "reasons");
    
    // Sort by weight (highest first)
    const sortedReasons = [...reasons].sort((a, b) => (b.weight || 0) - (a.weight || 0));
    
    sortedReasons.forEach(r => {
        const item = document.createElement('div');
        item.className = 'threat-item';

        const weight = r.weight || 0;
        let color = '#ffb300';
        let label = 'MED';
        
        if (weight >= 50) {
            color = '#ff0000';
            label = 'CRITICAL';
        } else if (weight >= 25) {
            color = '#ff003c';
            label = 'HIGH';
        } else if (weight >= 10) {
            color = '#ff3b3b';
            label = 'HIGH';
        }

        // Sanitize reason text
        const reasonText = escapeHtml(r.reason || 'Unknown threat');

        item.innerHTML = `
            <div class="threat-name">${reasonText}</div>
            <div class="threat-badge" style="background: ${color}">${label}</div>
        `;
        list.appendChild(item);
    });
}

function createBubbles() {
    const container = document.getElementById('bubble-container');
    if (!container) return;

    for (let i = 0; i < 15; i++) {
        const bubble = document.createElement('div');
        bubble.classList.add('bubble');
        bubble.style.left = Math.random() * 100 + '%';
        const size = Math.random() * 20 + 10;
        bubble.style.width = size + 'px';
        bubble.style.height = size + 'px';
        bubble.style.animationDuration = (Math.random() * 5 + 5) + 's';
        bubble.style.animationDelay = (Math.random() * 5) + 's';
        container.appendChild(bubble);
    }
}

function showError(msg) {
    const reasonsList = document.getElementById('reasonsList');
    if (reasonsList) {
        reasonsList.innerHTML = `
            <div style="padding:10px; color:#ff6b6b; font-size:12px;">${escapeHtml(msg)}</div>
        `;
    }
}

// ============================================
// BUTTON HANDLERS (DIRECT BYPASS - NO CONFIRMATION)
// ============================================

function setupButtons() {
    console.log("Setting up buttons");

    // Close button
    const closeBtn = document.getElementById('closeBtn');
    if (closeBtn) {
        closeBtn.onclick = async () => {
            console.log("Close clicked");
            try {
                const tabs = await browserAPI.tabs.query({ active: true, currentWindow: true });
                if (tabs && tabs[0]) {
                    await browserAPI.tabs.remove(tabs[0].id);
                } else {
                    window.close();
                }
            } catch (e) {
                console.error("Close failed:", e);
                window.close();
            }
        };
    }

    // Go back button
    const goBackBtn = document.getElementById('goBackBtn');
    if (goBackBtn) {
        goBackBtn.onclick = () => {
            console.log("Go back clicked");
            window.history.back();
        };
    }

    // Continue button - DIRECT BYPASS (NO CONFIRMATION)
    const continueBtn = document.getElementById('continueBtn');
    if (continueBtn) {
        continueBtn.onclick = async () => {
            if (bypassAttempted) {
                console.log("Bypass already attempted");
                return;
            }

            bypassAttempted = true;
            console.log("Continue clicked - bypassing directly to:", blockedUrl);

            // Disable button immediately
            continueBtn.disabled = true;
            continueBtn.textContent = 'Setting bypass...';

            try {
                // Validate URL one more time
                if (!isValidURL(blockedUrl)) {
                    throw new Error("Invalid URL");
                }

                // Set bypass in background
                console.log("Sending bypass message...");

                const response = await browserAPI.runtime.sendMessage({
                    action: "setTemporaryBypass",
                    url: blockedUrl
                });

                console.log("Bypass response:", response);

                if (!response || response.error) {
                    throw new Error(response ? response.error : "No response from background");
                }

                // Wait briefly for bypass to register
                continueBtn.textContent = 'Redirecting...';
                await new Promise(resolve => setTimeout(resolve, 300));

                // Redirect directly to the blocked site
                console.log("✅ Redirecting to:", blockedUrl);
                window.location.href = blockedUrl;

            } catch (error) {
                console.error("Bypass failed:", error);
                
                // Show error to user
                const errorMsg = document.createElement('div');
                errorMsg.style.cssText = `
                    position: fixed;
                    top: 50%;
                    left: 50%;
                    transform: translate(-50%, -50%);
                    background: #ff003c;
                    color: white;
                    padding: 20px 30px;
                    border-radius: 12px;
                    z-index: 999999;
                    text-align: center;
                    box-shadow: 0 10px 40px rgba(0,0,0,0.5);
                `;
                errorMsg.innerHTML = `
                    <div style="font-size: 24px; margin-bottom: 10px;">❌</div>
                    <div style="font-weight: bold; margin-bottom: 5px;">Failed to Proceed</div>
                    <div style="font-size: 12px;">${escapeHtml(error.message)}</div>
                `;
                document.body.appendChild(errorMsg);

                // Remove error after 3 seconds
                setTimeout(() => errorMsg.remove(), 3000);

                // Re-enable button
                continueBtn.disabled = false;
                continueBtn.textContent = 'Take the Bait (Unsafe)';
                bypassAttempted = false;
            }
        };
    }
}

function disableContinueButton() {
    const continueBtn = document.getElementById('continueBtn');
    if (continueBtn) {
        continueBtn.disabled = true;
        continueBtn.style.opacity = '0.3';
        continueBtn.style.cursor = 'not-allowed';
        continueBtn.textContent = 'Cannot Proceed';
    }
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
        console.log("Warning page hidden - user switched tabs");
    } else {
        console.log("Warning page visible again");
    }
});

// Prevent accidental back button during redirect
window.addEventListener('popstate', function(event) {
    if (!bypassAttempted) {
        console.log("Popstate detected - keeping user on warning page");
        history.pushState(null, document.title, location.href);
    }
});

// Initial history state
history.pushState(null, document.title, location.href);

console.log("Warning script loaded - Direct bypass mode enabled");