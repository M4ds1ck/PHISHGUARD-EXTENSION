// popup.js - FIXED - Shows real analysis even on bypassed sites
console.log("Popup initializing...");

const browserAPI = browser;
console.log("Browser: Firefox");

let currentTab = null;
let analysisComplete = false;

// ============================================
// INITIALIZATION
// ============================================

document.addEventListener('DOMContentLoaded', async () => {
    console.log("DOM loaded");

    try {
        // Initialize radar first
        const radar = new RadarScope('radar');
        radar.start();
        console.log("Radar started");

        // Get current tab with timeout
        const tabs = await Promise.race([
            browserAPI.tabs.query({ active: true, currentWindow: true }),
            new Promise((_, reject) => setTimeout(() => reject(new Error('Tab query timeout')), 3000))
        ]);

        if (!tabs || tabs.length === 0) {
            console.error("No active tab found");
            showError("No active tab");
            return;
        }

        currentTab = tabs[0];
        const url = currentTab.url;

        console.log("Current tab:", { id: currentTab.id, url: url });

        // Display URL
        displayURL(url);

        // Check if system page
        if (!url || url.startsWith('about:') || url.startsWith('moz-extension:')) {
            console.log("System page detected");
            showSafe();
            radar.setRiskLevel(0);
            setupButtons();
            return;
        }

        // Load stats (non-blocking)
        loadStats();

        // Analyze URL with FORCE flag to ignore bypass
        await analyzeURL(url, radar, true); // TRUE = force analysis even if bypassed

        // Setup buttons
        setupButtons();

        console.log("Initialization complete");

    } catch (error) {
        console.error("Initialization error:", error);
        showError("Failed to initialize: " + error.message);
    }
});

// ============================================
// URL DISPLAY
// ============================================

function displayURL(url) {
    const urlEl = document.getElementById('currentUrl');
    if (!urlEl) return;

    try {
        if (url.startsWith('about:') || url.startsWith('moz-extension:')) {
            urlEl.textContent = "System Page";
            return;
        }

        const urlObj = new URL(url);
        urlEl.textContent = urlObj.hostname;
        console.log("Displayed hostname:", urlObj.hostname);
    } catch (e) {
        console.error("URL parse error:", e);
        urlEl.textContent = "Invalid URL";
    }
}

// ============================================
// STATS LOADING
// ============================================

async function loadStats() {
    try {
        const response = await Promise.race([
            browserAPI.runtime.sendMessage({ action: "getStats" }),
            new Promise((_, reject) => setTimeout(() => reject(new Error('Stats timeout')), 2000))
        ]);

        console.log("Stats received:", response);
        if (response && !response.error) {
            updateStats(response);
        }
    } catch (error) {
        console.warn("Stats loading failed:", error);
        updateStats({ sitesScanned: 0, threatsBlocked: 0 });
    }
}

// ============================================
// URL ANALYSIS (FIXED - Force real analysis)
// ============================================

async function analyzeURL(url, radar, forceAnalysis = false) {
    console.log("Analyzing URL:", url, "| Force:", forceAnalysis);

    try {
        const response = await Promise.race([
            browserAPI.runtime.sendMessage({
                action: "analyzeUrl",
                url: url,
                forceAnalysis: forceAnalysis // NEW: Tell background to ignore bypass
            }),
            new Promise((_, reject) => setTimeout(() => reject(new Error('Analysis timeout')), 5000))
        ]);

        console.log("Analysis response:", response);

        if (!response) {
            throw new Error("No response from background script");
        }

        if (response.error) {
            throw new Error(response.error);
        }

        // Show bypass indicator if site was bypassed
        if (response.bypassed && !forceAnalysis) {
            showBypassedWarning();
        }

        // Update UI with results
        if (typeof response.score === 'number') {
            showRisk(response);
            radar.setRiskLevel(response.score);
            analysisComplete = true;
        } else {
            showSafe();
            radar.setRiskLevel(0);
        }

    } catch (error) {
        console.error("Analysis failed:", error);
        showError("Analysis failed: " + error.message);
        radar.setRiskLevel(0);
    }
}

// ============================================
// BYPASSED WARNING BANNER
// ============================================

function showBypassedWarning() {
    const banner = document.createElement('div');
    banner.style.cssText = `
        background: linear-gradient(135deg, #ffb300 0%, #ff6b00 100%);
        color: white;
        padding: 10px 20px;
        text-align: center;
        font-size: 11px;
        font-weight: 600;
        border-radius: 8px;
        margin: 15px 20px;
        box-shadow: 0 2px 10px rgba(255, 179, 0, 0.3);
    `;
    banner.innerHTML = `
        ⚠️ You bypassed protection for this site
    `;
    
    const urlDisplay = document.getElementById('urlDisplay');
    if (urlDisplay && urlDisplay.parentElement) {
        urlDisplay.parentElement.insertBefore(banner, urlDisplay.nextSibling);
    }
}

// ============================================
// UI UPDATES
// ============================================

function showRisk(data) {
    console.log("Showing risk:", data);

    const scoreEl = document.getElementById('score');
    const statusEl = document.getElementById('status');
    const logList = document.getElementById('logList');

    if (!scoreEl || !statusEl || !logList) {
        console.error("UI elements missing");
        return;
    }

    const score = Math.round(data.score || 0);
    
    // Animate score
    animateScore(score);

    // Remove all state classes
    document.body.classList.remove('state-safe', 'state-warning', 'state-danger');

    // Set state based on thresholds
    if (score >= 50) {
        statusEl.textContent = "THREAT DETECTED";
        document.body.classList.add('state-danger');
    } else if (score >= 20) {
        statusEl.textContent = "CAUTION";
        document.body.classList.add('state-warning');
    } else if (score > 0) {
        statusEl.textContent = "LOW RISK";
        document.body.classList.add('state-warning');
    } else {
        statusEl.textContent = "SECURE";
        document.body.classList.add('state-safe');
    }

    // Display reasons
    logList.innerHTML = '';

    if (data.reasons && data.reasons.length > 0) {
        console.log("Rendering", data.reasons.length, "reasons");
        
        // Sort by weight (highest first)
        const sortedReasons = [...data.reasons].sort((a, b) => b.weight - a.weight);
        
        sortedReasons.forEach(r => {
            const item = document.createElement('div');
            item.className = 'log-item';
            
            // Sanitize reason text
            const reasonText = escapeHtml(r.reason || 'Unknown threat');
            const weightText = r.weight ? `+${r.weight}` : '';
            
            item.innerHTML = `
                <div class="log-title">
                    ${reasonText}
                    ${weightText ? `<span class="log-weight">${weightText}</span>` : ''}
                </div>
            `;
            logList.appendChild(item);
        });
    } else if (score === 0) {
        showSafe();
    } else {
        logList.innerHTML = `
            <div style="padding:10px; color:var(--neon-orange); font-size:12px;">
                Suspicious activity detected
            </div>
        `;
    }
}

function showSafe() {
    console.log("Showing safe state");

    document.getElementById('score').textContent = '0';
    document.getElementById('status').textContent = 'SECURE';
    
    document.body.classList.remove('state-danger', 'state-warning');
    document.body.classList.add('state-safe');

    document.getElementById('logList').innerHTML = `
        <div style="padding:10px; color:var(--neon-green); font-size:12px; display:flex; align-items:center; gap:8px;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                <polyline points="22 4 12 14.01 9 11.01"/>
            </svg>
            No threats detected
        </div>
    `;
}

function showError(msg) {
    console.error("Showing error:", msg);

    document.getElementById('score').textContent = 'ERR';
    document.getElementById('status').textContent = 'ERROR';
    document.body.classList.add('state-warning');
    
    document.getElementById('logList').innerHTML = `
        <div style="padding:10px; color:#ff6b6b; font-size:12px;">${escapeHtml(msg)}</div>
    `;
}

function updateStats(stats) {
    const scannedEl = document.getElementById('statScanned');
    const blockedEl = document.getElementById('statBlocked');

    if (scannedEl) scannedEl.textContent = stats.sitesScanned || 0;
    if (blockedEl) blockedEl.textContent = stats.threatsBlocked || 0;
}

// ============================================
// SCORE ANIMATION
// ============================================

function animateScore(target) {
    const scoreEl = document.getElementById('score');
    if (!scoreEl) return;

    let current = 0;
    const step = Math.ceil(target / 50);
    const duration = 1000;
    const interval = duration / (target / step);

    const timer = setInterval(() => {
        current += step;
        if (current >= target) {
            current = target;
            clearInterval(timer);
        }
        scoreEl.textContent = current;
    }, interval);
}

// ============================================
// BUTTON HANDLERS
// ============================================

function setupButtons() {
    console.log("Setting up buttons");

    // Rescan button
    const rescanBtn = document.getElementById('rescanBtn');
    if (rescanBtn) {
        rescanBtn.onclick = () => {
            console.log("Rescan clicked");
            window.location.reload();
        };
    }

    // Whitelist button
    const whitelistBtn = document.getElementById('whitelistBtn');
    if (whitelistBtn) {
        whitelistBtn.onclick = async () => {
            console.log("Whitelist clicked");
            
            if (!currentTab || !currentTab.url) {
                alert("No tab URL available");
                return;
            }

            try {
                const hostname = new URL(currentTab.url).hostname;
                console.log("Whitelisting:", hostname);

                whitelistBtn.disabled = true;
                whitelistBtn.textContent = "Adding...";

                const response = await browserAPI.runtime.sendMessage({
                    action: "addToWhitelist",
                    domain: hostname
                });

                console.log("Whitelist response:", response);

                if (response && response.success) {
                    alert(`${hostname} added to whitelist`);
                    window.close();
                } else {
                    throw new Error(response?.error || "Failed to whitelist");
                }
            } catch (e) {
                console.error("Whitelist error:", e);
                alert("Failed to whitelist: " + e.message);
                whitelistBtn.disabled = false;
                whitelistBtn.textContent = "Trust";
            }
        };
    }

    // Blacklist button
    const blacklistBtn = document.getElementById('blacklistBtn');
    if (blacklistBtn) {
        blacklistBtn.onclick = async () => {
            console.log("Blacklist clicked");
            
            if (!currentTab || !currentTab.url) {
                alert("No tab URL available");
                return;
            }

            try {
                const hostname = new URL(currentTab.url).hostname;

                if (!confirm(`Block ${hostname}?\n\nThis site will be blocked on all future visits.`)) {
                    return;
                }

                console.log("Blacklisting:", hostname);

                blacklistBtn.disabled = true;
                blacklistBtn.textContent = "Blocking...";

                const response = await browserAPI.runtime.sendMessage({
                    action: "addToBlacklist",
                    domain: hostname
                });

                console.log("Blacklist response:", response);

                if (response && response.success) {
                    await browserAPI.tabs.reload(currentTab.id);
                    window.close();
                } else {
                    throw new Error(response?.error || "Failed to blacklist");
                }
            } catch (e) {
                console.error("Blacklist error:", e);
                alert("Failed to blacklist: " + e.message);
                blacklistBtn.disabled = false;
                blacklistBtn.textContent = "Block";
            }
        };
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
// RADAR ANIMATION
// ============================================

class RadarScope {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) {
            console.error("Canvas not found:", canvasId);
            return;
        }

        this.ctx = this.canvas.getContext('2d');
        this.angle = 0;
        this.risk = 0;
        this.animationFrame = null;

        // Setup canvas
        const dpr = window.devicePixelRatio || 1;
        const rect = this.canvas.getBoundingClientRect();
        this.canvas.width = rect.width * dpr;
        this.canvas.height = rect.height * dpr;
        this.ctx.scale(dpr, dpr);
        this.width = rect.width;
        this.height = rect.height;
        this.cx = this.width / 2;
        this.cy = this.height / 2;

        console.log("Radar initialized");
    }

    setRiskLevel(score) {
        this.risk = Math.max(0, Math.min(100, score));
        console.log("Radar risk level:", this.risk);
    }

    start() {
        if (this.canvas && !this.animationFrame) {
            this.animate();
        }
    }

    stop() {
        if (this.animationFrame) {
            cancelAnimationFrame(this.animationFrame);
            this.animationFrame = null;
        }
    }

    animate() {
        if (!this.ctx) return;

        const ctx = this.ctx;
        const cx = this.cx;
        const cy = this.cy;
        const radius = Math.min(cx, cy) - 10;

        // Clear canvas
        ctx.clearRect(0, 0, this.width, this.height);

        // Determine color based on risk
        let color = '0, 255, 157'; // Green
        if (this.risk >= 50) {
            color = '255, 59, 59'; // Red
        } else if (this.risk >= 20) {
            color = '255, 179, 0'; // Orange
        }

        // Draw concentric circles
        ctx.strokeStyle = `rgba(${color}, 0.2)`;
        ctx.lineWidth = 1;

        [0.3, 0.6, 0.9].forEach(scale => {
            ctx.beginPath();
            ctx.arc(cx, cy, radius * scale, 0, Math.PI * 2);
            ctx.stroke();
        });

        // Draw crosshairs
        ctx.beginPath();
        ctx.moveTo(cx, cy - radius);
        ctx.lineTo(cx, cy + radius);
        ctx.moveTo(cx - radius, cy);
        ctx.lineTo(cx + radius, cy);
        ctx.stroke();

        // Draw sweep line
        this.angle += 0.03;
        ctx.save();
        ctx.translate(cx, cy);
        ctx.rotate(this.angle);

        // Sweep gradient
        ctx.beginPath();
        ctx.moveTo(0, 0);
        ctx.arc(0, 0, radius, 0, 0.4);
        ctx.lineTo(0, 0);
        ctx.closePath();
        ctx.fillStyle = `rgba(${color}, 0.1)`;
        ctx.fill();

        // Sweep line
        ctx.strokeStyle = `rgba(${color}, 1)`;
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.moveTo(0, 0);
        ctx.lineTo(radius, 0);
        ctx.stroke();

        ctx.restore();

        // Draw blips for threats
        if (this.risk > 0 && Math.random() > 0.95) {
            const angle = Math.random() * Math.PI * 2;
            const dist = Math.random() * radius * 0.8;
            const bx = cx + Math.cos(angle) * dist;
            const by = cy + Math.sin(angle) * dist;
            
            ctx.fillStyle = `rgba(${color}, 0.8)`;
            ctx.beginPath();
            ctx.arc(bx, by, 2, 0, Math.PI * 2);
            ctx.fill();
        }

        // Continue animation
        this.animationFrame = requestAnimationFrame(() => this.animate());
    }
}

console.log("Popup script loaded");