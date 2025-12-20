// popup.js - Enhanced Popup Logic
console.log("PhishGuard Popup: Initializing...");

// DOM Elements
const radarContainer = document.getElementById('radarContainer');
const scoreEl = document.getElementById('score');
const statusEl = document.getElementById('status');
const urlDisplay = document.getElementById('currentUrl');
const logList = document.getElementById('logList');
const rescanBtn = document.getElementById('rescanBtn');
const whitelistBtn = document.getElementById('whitelistBtn');
const blacklistBtn = document.getElementById('blacklistBtn');
const statScanned = document.getElementById('statScanned');
const statBlocked = document.getElementById('statBlocked');

// Canvas Animation
const canvas = document.getElementById('radar');
const ctx = canvas.getContext('2d');
let ringColor = '#00f3ff';
let angle = 0;
let currentTab = null;
let currentHostname = null;

// Set canvas size
function resizeCanvas() {
    const rect = radarContainer.getBoundingClientRect();
    canvas.width = rect.width;
    canvas.height = rect.height;
}
resizeCanvas();

// Radar animation
function animateRadar() {
    const width = canvas.width;
    const height = canvas.height;
    const centerX = width / 2;
    const centerY = height / 2;

    ctx.clearRect(0, 0, width, height);

    // Draw concentric circles
    ctx.strokeStyle = ringColor;
    ctx.lineWidth = 1.5;
    ctx.globalAlpha = 0.3;

    for (let i = 1; i <= 3; i++) {
        ctx.beginPath();
        ctx.arc(centerX, centerY, 40 * i, 0, Math.PI * 2);
        ctx.stroke();
    }

    // Draw scanning line
    ctx.save();
    ctx.translate(centerX, centerY);
    ctx.rotate(angle);
    ctx.globalAlpha = 0.8;
    ctx.lineWidth = 3;
    ctx.strokeStyle = ringColor;
    ctx.shadowBlur = 15;
    ctx.shadowColor = ringColor;

    ctx.beginPath();
    ctx.moveTo(0, 0);
    ctx.lineTo(0, -100);
    ctx.stroke();

    ctx.restore();

    angle += 0.05;
    requestAnimationFrame(animateRadar);
}
animateRadar();

// ============================================
// UI STATE MANAGEMENT
// ============================================

function setUIState(state) {
    // Remove all state classes
    radarContainer.classList.remove('state-safe', 'state-warning', 'state-danger');
    
    // Add appropriate state class
    radarContainer.classList.add(`state-${state}`);
    
    // Update ring color
    if (state === 'safe') {
        ringColor = '#00ff9d';
    } else if (state === 'warning') {
        ringColor = '#fcee0a';
    } else if (state === 'danger') {
        ringColor = '#ff003c';
    } else {
        ringColor = '#00f3ff';
    }
}

function showLoading() {
    logList.innerHTML = `
        <div class="loading">
            <div class="spinner"></div>
            <div>Analyzing security threats...</div>
        </div>
    `;
    scoreEl.textContent = '...';
    statusEl.textContent = 'SCANNING';
    setUIState('neutral');
}

function showError(message) {
    logList.innerHTML = `
        <div class="empty-state">
            <div class="empty-icon">⚠️</div>
            <div class="empty-text">${message}</div>
        </div>
    `;
    scoreEl.textContent = '--';
    statusEl.textContent = 'ERROR';
    setUIState('neutral');
}

function showSystemPage() {
    logList.innerHTML = `
        <div class="empty-state">
            <div class="empty-icon">🔒</div>
            <div class="empty-text">
                PhishGuard is inactive on browser system pages.<br>
                Navigate to a website to enable protection.
            </div>
        </div>
    `;
    scoreEl.textContent = '--';
    statusEl.textContent = 'SYSTEM PAGE';
    urlDisplay.textContent = 'Browser Internal Page';
    setUIState('neutral');
    
    // Disable action buttons
    rescanBtn.disabled = true;
    whitelistBtn.disabled = true;
    blacklistBtn.disabled = true;
}

// ============================================
// DATA RENDERING
// ============================================

function renderReport(data) {
    console.log("Rendering report:", data);
    
    // Update score
    scoreEl.textContent = data.score + '%';
    
    // Update URL
    if (data.url) {
        try {
            const url = new URL(data.url);
            currentHostname = url.hostname;
            urlDisplay.textContent = url.hostname + url.pathname;
        } catch (e) {
            urlDisplay.textContent = data.url;
        }
    }
    
    // Update status and color
    if (data.score >= 75) {
        statusEl.textContent = 'CRITICAL THREAT';
        setUIState('danger');
    } else if (data.score >= 50) {
        statusEl.textContent = 'THREAT DETECTED';
        setUIState('danger');
    } else if (data.score >= 25) {
        statusEl.textContent = 'SUSPICIOUS';
        setUIState('warning');
    } else if (data.score > 0) {
        statusEl.textContent = 'LOW RISK';
        setUIState('warning');
    } else {
        statusEl.textContent = 'SECURE';
        setUIState('safe');
    }
    
    // Render detection reasons
    logList.innerHTML = '';
    
    if (!data.reasons || data.reasons.length === 0) {
        logList.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">✓</div>
                <div class="empty-text">
                    No security threats detected.<br>
                    This site appears to be safe.
                </div>
            </div>
        `;
        return;
    }
    
    // Sort reasons by weight (highest first)
    const sortedReasons = [...data.reasons].sort((a, b) => {
        const weightA = a.weight || 0;
        const weightB = b.weight || 0;
        return weightB - weightA;
    });
    
    sortedReasons.forEach(item => {
        const weight = item.weight || 0;
        const logItem = document.createElement('div');
        logItem.className = 'log-item';
        
        // Set border color based on severity
        if (weight >= 50) {
            logItem.style.borderLeftColor = '#ff003c';
        } else if (weight >= 25) {
            logItem.style.borderLeftColor = '#ffb300';
        } else if (weight >= 10) {
            logItem.style.borderLeftColor = '#fcee0a';
        } else {
            logItem.style.borderLeftColor = '#4caf50';
        }
        
        // Build log item HTML
        let html = `
            <div class="log-title">
                <span>${item.reason}</span>
                <span class="log-weight">+${weight} pts</span>
            </div>
        `;
        
        if (item.detail) {
            html += `<div class="log-detail">${item.detail}</div>`;
        }
        
        logItem.innerHTML = html;
        logList.appendChild(logItem);
    });
}

// ============================================
// STATISTICS UPDATE
// ============================================

async function updateStats() {
    try {
        chrome.runtime.sendMessage({ action: "getStats" }, (stats) => {
            if (stats) {
                statScanned.textContent = stats.sitesScanned || 0;
                statBlocked.textContent = stats.threatsBlocked || 0;
            }
        });
    } catch (error) {
        console.error("Error updating stats:", error);
    }
}

// ============================================
// SCAN LOGIC
// ============================================

async function performScan() {
    if (!currentTab || !currentTab.id) {
        showError("No active tab found");
        return;
    }
    
    showLoading();
    
    // First check cache
    chrome.runtime.sendMessage(
        { action: "getCachedRisk", tabId: currentTab.id },
        (cached) => {
            if (cached) {
                console.log("Using cached data");
                renderReport(cached);
                return;
            }
            
            // No cache, ping content script
            chrome.tabs.sendMessage(
                currentTab.id,
                { action: "ping" },
                (response) => {
                    if (chrome.runtime.lastError) {
                        console.warn("Content script not responding:", chrome.runtime.lastError);
                        
                        // Try to reload the tab
                        showError("Connection lost. Click Rescan to retry.");
                        setTimeout(() => {
                            chrome.runtime.sendMessage(
                                { action: "forceFixTab", tabId: currentTab.id }
                            );
                        }, 1000);
                        return;
                    }
                    
                    // Wait for the scan to complete and report back
                    setTimeout(() => {
                        chrome.runtime.sendMessage(
                            { action: "getCachedRisk", tabId: currentTab.id },
                            (data) => {
                                if (data) {
                                    renderReport(data);
                                } else {
                                    showError("No scan results available. Try rescanning.");
                                }
                            }
                        );
                    }, 500);
                }
            );
        }
    );
    
    // Update stats
    updateStats();
}

// ============================================
// ACTION HANDLERS
// ============================================

rescanBtn.addEventListener('click', async () => {
    if (!currentTab || !currentTab.id) return;
    
    console.log("Manual rescan triggered");
    
    // Clear cache first
    chrome.runtime.sendMessage(
        { action: "clearCache", tabId: currentTab.id },
        () => {
            // Trigger new scan
            chrome.tabs.sendMessage(
                currentTab.id,
                { action: "manualScan" },
                () => {
                    if (chrome.runtime.lastError) {
                        showError("Cannot scan this page. Content script unavailable.");
                        return;
                    }
                    
                    // Wait and fetch results
                    showLoading();
                    setTimeout(() => performScan(), 500);
                }
            );
        }
    );
});

whitelistBtn.addEventListener('click', async () => {
    if (!currentHostname || !currentTab) return;
    
    const confirmed = confirm(
        `Add "${currentHostname}" to trusted domains?\n\n` +
        `This domain will always be marked as safe.`
    );
    
    if (confirmed) {
        chrome.runtime.sendMessage(
            {
                action: "addToWhitelist",
                domain: currentHostname,
                tabId: currentTab.id
            },
            () => {
                console.log(`Added ${currentHostname} to whitelist`);
                // Rescan to update UI
                setTimeout(() => performScan(), 200);
            }
        );
    }
});

blacklistBtn.addEventListener('click', async () => {
    if (!currentHostname || !currentTab) return;
    
    const confirmed = confirm(
        `Block "${currentHostname}"?\n\n` +
        `This domain will always be flagged as dangerous.`
    );
    
    if (confirmed) {
        chrome.runtime.sendMessage(
            {
                action: "addToBlacklist",
                domain: currentHostname,
                tabId: currentTab.id
            },
            () => {
                console.log(`Added ${currentHostname} to blacklist`);
                // Rescan to update UI
                setTimeout(() => performScan(), 200);
            }
        );
    }
});

// ============================================
// INITIALIZATION
// ============================================

async function initialize() {
    console.log("Initializing popup...");
    
    try {
        // Get current active tab
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        currentTab = tabs[0];
        
        if (!currentTab || !currentTab.url) {
            showError("Cannot access this page");
            return;
        }
        
        // Check if it's a system page
        const url = currentTab.url;
        if (url.startsWith('chrome:') || 
            url.startsWith('about:') || 
            url.startsWith('moz-extension:') ||
            url.startsWith('chrome-extension:') ||
            url.startsWith('edge:') ||
            url.startsWith('opera:')) {
            showSystemPage();
            return;
        }
        
        // Perform scan
        await performScan();
        
    } catch (error) {
        console.error("Initialization error:", error);
        showError("Failed to initialize: " + error.message);
    }
}

// Start when DOM is ready
document.addEventListener('DOMContentLoaded', initialize);

console.log("PhishGuard Popup: Ready");