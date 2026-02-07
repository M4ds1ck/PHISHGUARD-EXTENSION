// popup.js - v3.0.0 with Force Analysis, Privacy Consent & Error Boundaries
console.log("[Popup] Initializing PhishGuard DeepSea v3.0.0");
const browserAPI = browser;

let currentTab = null;
let analysisComplete = false;
let radarInstance = null;

// ============================================
// INITIALIZATION WITH TIMEOUTS & ERROR HANDLING
// ============================================
document.addEventListener('DOMContentLoaded', async () => {
  console.log("[Popup] DOM loaded");
  
  try {
    // Initialize radar visualization
    radarInstance = new RadarScope('radar');
    radarInstance.start();
    console.log("[Popup] Radar visualization started");

    // Get current tab with timeout protection
    const tabs = await Promise.race([
      browserAPI.tabs.query({ active: true, currentWindow: true }),
      new Promise((_, reject) => setTimeout(() => reject(new Error('Tab query timeout after 3s')), 3000))
    ]);

    if (!tabs || tabs.length === 0) {
      throw new Error("No active tab found");
    }

    currentTab = tabs[0];
    const url = currentTab.url || '';
    console.log(`[Popup] Analyzing tab ${currentTab.id}: ${url.substring(0, 50)}...`);

    // Display URL with validation
    displayURL(url);

    // Handle system pages immediately
    if (!url || url.startsWith('about:') || url.startsWith('moz-extension:') || 
        url.startsWith('chrome:') || url.startsWith('edge:') || url.startsWith('file:')) {
      console.log("[Popup] System page detected - showing safe status");
      showSafe();
      radarInstance.setRiskLevel(0);
      setupButtons();
      return;
    }

    // Load stats asynchronously (non-blocking)
    loadStats().catch(err => console.warn("[Popup] Stats load failed:", err));

    // CRITICAL: Force analysis to ignore bypasses and show real threat level
    await analyzeURL(url, true); // forceAnalysis = true

    // Setup interactive buttons
    setupButtons();

    console.log("[Popup] ✅ Initialization complete");
    
  } catch (error) {
    console.error("[Popup] Initialization failed:", error);
    showError(`Initialization failed: ${error.message}`);
    if (radarInstance) radarInstance.setRiskLevel(0);
  }
});

// ============================================
// URL DISPLAY WITH SANITIZATION
// ============================================
function displayURL(url) {
  const urlEl = document.getElementById('currentUrl');
  const urlDisplay = document.getElementById('urlDisplay');
  
  if (!urlEl || !urlDisplay) return;
  
  // Show loading state
  urlDisplay.classList.add('loading');
  
  try {
    if (!url || url.startsWith('about:') || url.startsWith('moz-extension:')) {
      urlEl.textContent = "System Page";
      urlDisplay.classList.remove('loading');
      return;
    }

    const urlObj = new URL(url);
    // Display only hostname for security and clarity
    urlEl.textContent = urlObj.hostname.replace(/^www\./, '');
    urlDisplay.title = url; // Full URL in tooltip
    console.log(`[Popup] Displaying hostname: ${urlEl.textContent}`);
    
  } catch (e) {
    console.error("[Popup] URL parse error:", e);
    urlEl.textContent = "Invalid URL";
  } finally {
    urlDisplay.classList.remove('loading');
  }
}

// ============================================
// STATS LOADING WITH ERROR HANDLING
// ============================================
async function loadStats() {
  try {
    const response = await Promise.race([
      browserAPI.runtime.sendMessage({ action: "getStats" }),
      new Promise((_, reject) => setTimeout(() => reject(new Error('Stats timeout after 2s')), 2000))
    ]);
    
    if (response && !response.error) {
      updateStats(response);
      console.log("[Popup] Stats loaded:", response);
    } else {
      console.warn("[Popup] Invalid stats response:", response);
      updateStats({ sitesScanned: 0, threatsBlocked: 0 });
    }
  } catch (error) {
    console.warn("[Popup] Stats loading failed:", error.message);
    updateStats({ sitesScanned: 0, threatsBlocked: 0 });
  }
}

// ============================================
// URL ANALYSIS WITH FORCE FLAG & TIMEOUT
// ============================================
async function analyzeURL(url, forceAnalysis = false) {
  console.log(`[Popup] Analyzing URL (force=${forceAnalysis}):`, url.substring(0, 60));
  
  try {
    // Show loading state in analysis section
    const logList = document.getElementById('logList');
    if (logList) {
      logList.innerHTML = `
        <div style="padding:15px; text-align:center; color:var(--text-secondary);">
          <div class="loading-spinner"></div>
          ${forceAnalysis ? 'Forcing deep analysis...' : 'Scanning threat vectors...'}
        </div>
      `;
    }

    const response = await Promise.race([
      browserAPI.runtime.sendMessage({
        action: "analyzeUrl",
        url: url,
        forceAnalysis: forceAnalysis // Critical: bypass cache for accurate status
      }),
      new Promise((_, reject) => setTimeout(() => reject(new Error('Analysis timeout after 5s')), 5000))
    ]);

    console.log("[Popup] Analysis response:", response);

    if (!response) {
      throw new Error("No response from background script");
    }

    if (response.error) {
      throw new Error(response.error);
    }

    // Show bypass warning if site was bypassed (but we're forcing analysis)
    if (response.bypassed && !forceAnalysis) {
      showBypassedWarning();
    }

    // Update UI with results
    if (typeof response.score === 'number') {
      showRisk(response);
      if (radarInstance) radarInstance.setRiskLevel(response.score);
      analysisComplete = true;
    } else {
      showSafe();
      if (radarInstance) radarInstance.setRiskLevel(0);
    }

  } catch (error) {
    console.error("[Popup] Analysis failed:", error);
    showError(`Analysis failed: ${error.message}`);
    if (radarInstance) radarInstance.setRiskLevel(0);
  }
}

// ============================================
// BYPASSED WARNING BANNER
// ============================================
function showBypassedWarning() {
  const warningEl = document.getElementById('bypassWarning');
  if (warningEl) {
    warningEl.classList.remove('hidden');
    console.log("[Popup] Showing bypass warning");
  }
}

// ============================================
// UI STATE UPDATERS
// ============================================
function showRisk(data) {
  console.log("[Popup] Showing risk analysis:", data.score);
  
  const scoreEl = document.getElementById('score');
  const statusEl = document.getElementById('status');
  const logList = document.getElementById('logList');
  
  if (!scoreEl || !statusEl || !logList) {
    console.error("[Popup] UI elements missing for risk display");
    return;
  }

  const score = Math.round(data.score || 0);
  
  // Animate score display
  animateScore(scoreEl, score);
  
  // Reset state classes
  document.body.className = '';
  
  // Set visual state based on score thresholds
  if (score >= 75) {
    statusEl.textContent = "CRITICAL THREAT";
    document.body.classList.add('state-danger');
  } else if (score >= 50) {
    statusEl.textContent = "HIGH RISK";
    document.body.classList.add('state-danger');
  } else if (score >= 25) {
    statusEl.textContent = "CAUTION";
    document.body.classList.add('state-warning');
  } else if (score > 0) {
    statusEl.textContent = "LOW RISK";
    document.body.classList.add('state-warning');
  } else {
    showSafe();
    return;
  }

  // Display threat reasons
  logList.innerHTML = '';
  
  if (data.reasons && data.reasons.length > 0) {
    console.log(`[Popup] Rendering ${data.reasons.length} threat reasons`);
    
    // Sort by weight (highest first) and limit to top 10
    const sortedReasons = [...data.reasons]
      .sort((a, b) => (b.weight || 0) - (a.weight || 0))
      .slice(0, 10);
    
    sortedReasons.forEach(r => {
      const item = document.createElement('div');
      item.className = 'log-item';
      
      // Sanitize and format reason text
      const reasonText = escapeHtml(r.reason || 'Unknown threat');
      const weightText = r.weight ? `+${r.weight}` : '';
      const detailText = r.detail ? `: ${escapeHtml(r.detail)}` : '';
      
      item.innerHTML = `
        <div class="log-title">
          ${reasonText}${detailText}
          ${weightText ? `<span class="log-weight">${weightText}</span>` : ''}
        </div>
      `;
      logList.appendChild(item);
    });
    
    // Add note if we truncated results
    if (data.reasons.length > 10) {
      const moreItem = document.createElement('div');
      moreItem.style.cssText = 'padding:8px; text-align:center; font-size:0.85rem; color:var(--text-secondary); margin-top:8px;';
      moreItem.textContent = `+${data.reasons.length - 10} more threat vectors detected`;
      logList.appendChild(moreItem);
    }
  } else {
    logList.innerHTML = `
      <div style="padding:12px; color:var(--neon-orange); text-align:center;">
        Suspicious activity detected (score: ${score})
      </div>
    `;
  }
}

function showSafe() {
  console.log("[Popup] Showing safe status");
  
  document.getElementById('score').textContent = '0';
  document.getElementById('status').textContent = 'SECURE';
  document.body.className = 'state-safe';
  
  const logList = document.getElementById('logList');
  if (logList) {
    logList.innerHTML = `
      <div class="safe-message">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
          <polyline points="22 4 12 14.01 9 11.01"></polyline>
        </svg>
        <span>No threats detected • Connection secure</span>
      </div>
    `;
  }
}

function showError(msg) {
  console.error("[Popup] Displaying error:", msg);
  
  document.getElementById('score').textContent = 'ERR';
  document.getElementById('status').textContent = 'ERROR';
  document.body.className = 'state-warning';
  
  const logList = document.getElementById('logList');
  if (logList) {
    logList.innerHTML = `
      <div class="error-banner">
        <strong>⚠️ Analysis Error</strong><br>${escapeHtml(msg)}
      </div>
    `;
  }
}

function updateStats(stats) {
  const scannedEl = document.getElementById('statScanned');
  const blockedEl = document.getElementById('statBlocked');
  
  if (scannedEl) scannedEl.textContent = (stats.sitesScanned || 0).toLocaleString();
  if (blockedEl) blockedEl.textContent = (stats.threatsBlocked || 0).toLocaleString();
}

// ============================================
// SCORE ANIMATION
// ============================================
function animateScore(element, target) {
  if (!element) return;
  
  let current = 0;
  const step = Math.max(1, Math.ceil(target / 30));
  const duration = 800;
  const frames = duration / 16; // ~60fps
  const increment = target / frames;
  
  const animate = () => {
    current += increment;
    if (current >= target) {
      element.textContent = target;
      return;
    }
    element.textContent = Math.round(current);
    requestAnimationFrame(animate);
  };
  
  animate();
}

// ============================================
// BUTTON HANDLERS WITH VALIDATION
// ============================================
function setupButtons() {
  console.log("[Popup] Setting up interactive buttons");
  
  // Rescan button
  const rescanBtn = document.getElementById('rescanBtn');
  if (rescanBtn) {
    rescanBtn.addEventListener('click', () => {
      console.log("[Popup] Rescan triggered");
      if (currentTab?.url) {
        analyzeURL(currentTab.url, true); // Force fresh analysis
      } else {
        showError("No valid URL to rescan");
      }
    });
  }

  // Whitelist button
  const whitelistBtn = document.getElementById('whitelistBtn');
  if (whitelistBtn) {
    whitelistBtn.addEventListener('click', async () => {
      console.log("[Popup] Whitelist requested");
      
      if (!currentTab?.url) {
        alert("No active tab URL available");
        return;
      }

      try {
        const urlObj = new URL(currentTab.url);
        const hostname = urlObj.hostname.toLowerCase().replace(/^www\./, '');
        
        if (!confirm(`Add "${hostname}" to trusted sites?\n\nThis site will never be blocked by PhishGuard.`)) {
          return;
        }

        whitelistBtn.disabled = true;
        whitelistBtn.innerHTML = `<div class="loading-spinner"></div> Adding...`;
        
        const response = await browserAPI.runtime.sendMessage({
          action: "addToWhitelist",
          domain: hostname
        });

        if (response?.success) {
          console.log(`[Popup] ✅ ${hostname} added to whitelist`);
          alert(`✅ "${hostname}" has been added to your trusted sites`);
          window.close();
        } else {
          throw new Error(response?.error || "Unknown error");
        }
      } catch (e) {
        console.error("[Popup] Whitelist failed:", e);
        alert(`❌ Failed to whitelist site: ${e.message}`);
      } finally {
        whitelistBtn.disabled = false;
        whitelistBtn.innerHTML = `
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
          </svg>
          Trust
        `;
      }
    });
  }

  // Blacklist button
  const blacklistBtn = document.getElementById('blacklistBtn');
  if (blacklistBtn) {
    blacklistBtn.addEventListener('click', async () => {
      console.log("[Popup] Blacklist requested");
      
      if (!currentTab?.url) {
        alert("No active tab URL available");
        return;
      }

      try {
        const urlObj = new URL(currentTab.url);
        const hostname = urlObj.hostname.toLowerCase().replace(/^www\./, '');
        
        if (!confirm(`⚠️ PERMANENTLY BLOCK "${hostname}"?\n\nThis site will be blocked on all future visits. This action cannot be undone from the popup.`)) {
          return;
        }

        blacklistBtn.disabled = true;
        blacklistBtn.innerHTML = `<div class="loading-spinner"></div> Blocking...`;
        
        const response = await browserAPI.runtime.sendMessage({
          action: "addToBlacklist",
          domain: hostname
        });

        if (response?.success) {
          console.log(`[Popup] 🚫 ${hostname} added to blacklist`);
          // Reload tab and close popup
          await browserAPI.tabs.reload(currentTab.id);
          window.close();
        } else {
          throw new Error(response?.error || "Unknown error");
        }
      } catch (e) {
        console.error("[Popup] Blacklist failed:", e);
        alert(`❌ Failed to block site: ${e.message}`);
      } finally {
        blacklistBtn.disabled = false;
        blacklistBtn.innerHTML = `
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line>
          </svg>
          Block
        `;
      }
    });
  }
}

// ============================================
// RADAR VISUALIZATION CLASS (OPTIMIZED)
// ============================================
class RadarScope {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) {
      console.error("[Radar] Canvas element not found:", canvasId);
      return;
    }
    
    this.ctx = this.canvas.getContext('2d');
    this.angle = 0;
    this.riskLevel = 0;
    this.animationFrame = null;
    this.particles = [];
    
    // Setup canvas with DPR
    const dpr = window.devicePixelRatio || 1;
    const rect = this.canvas.getBoundingClientRect();
    this.canvas.width = rect.width * dpr;
    this.canvas.height = rect.height * dpr;
    this.ctx.scale(dpr, dpr);
    this.width = rect.width;
    this.height = rect.height;
    this.cx = this.width / 2;
    this.cy = this.height / 2;
    this.radius = Math.min(this.cx, this.cy) - 15;
    
    // Initialize particles
    this.initParticles();
    
    console.log("[Radar] Initialized with DPR:", dpr);
  }
  
  initParticles() {
    this.particles = [];
    const particleCount = 8 + Math.floor(this.riskLevel / 10);
    
    for (let i = 0; i < particleCount; i++) {
      this.particles.push({
        angle: Math.random() * Math.PI * 2,
        distance: Math.random() * this.radius * 0.8,
        size: 1.5 + Math.random() * 2,
        speed: 0.001 + Math.random() * 0.003,
        opacity: 0.4 + Math.random() * 0.6
      });
    }
  }
  
  setRiskLevel(score) {
    this.riskLevel = Math.max(0, Math.min(100, score));
    this.initParticles(); // Recreate particles based on risk
    console.log("[Radar] Risk level updated:", this.riskLevel);
  }
  
  start() {
    if (!this.ctx || this.animationFrame) return;
    this.animate();
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
    const radius = this.radius;
    
    // Clear canvas
    ctx.clearRect(0, 0, this.width, this.height);
    
    // Determine color based on risk level
    let color;
    if (this.riskLevel >= 75) color = '255, 0, 60';      // Critical red
    else if (this.riskLevel >= 50) color = '255, 59, 59'; // High risk red
    else if (this.riskLevel >= 25) color = '255, 179, 0'; // Warning orange
    else color = '0, 255, 157';                          // Safe green
    
    // Draw concentric circles
    ctx.strokeStyle = `rgba(${color}, 0.15)`;
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
    ctx.strokeStyle = `rgba(${color}, 0.3)`;
    ctx.stroke();
    
    // Draw sweep line with gradient
    this.angle = (this.angle + 0.02) % (Math.PI * 2);
    ctx.save();
    ctx.translate(cx, cy);
    ctx.rotate(this.angle);
    
    // Sweep gradient
    const gradient = ctx.createLinearGradient(0, 0, radius, 0);
    gradient.addColorStop(0, `rgba(${color}, 0.05)`);
    gradient.addColorStop(1, `rgba(${color}, 0.25)`);
    
    ctx.beginPath();
    ctx.moveTo(0, 0);
    ctx.arc(0, 0, radius, -0.3, 0.3);
    ctx.closePath();
    ctx.fillStyle = gradient;
    ctx.fill();
    
    // Sweep line
    ctx.strokeStyle = `rgba(${color}, 0.9)`;
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(0, 0);
    ctx.lineTo(radius, 0);
    ctx.stroke();
    
    ctx.restore();
    
    // Draw threat particles
    this.particles.forEach(p => {
      // Update position
      p.angle += p.speed;
      if (p.angle > Math.PI * 2) p.angle -= Math.PI * 2;
      
      // Calculate position
      const x = cx + Math.cos(p.angle) * p.distance;
      const y = cy + Math.sin(p.angle) * p.distance;
      
      // Draw particle
      ctx.fillStyle = `rgba(${color}, ${p.opacity})`;
      ctx.beginPath();
      ctx.arc(x, y, p.size, 0, Math.PI * 2);
      ctx.fill();
    });
    
    // Continue animation
    this.animationFrame = requestAnimationFrame(() => this.animate());
  }
}

// ============================================
// UTILITY FUNCTIONS
// ============================================
function escapeHtml(text) {
  if (typeof text !== 'string') return String(text);
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// ============================================
// PAGE VISIBILITY HANDLER
// ============================================
document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    console.log("[Popup] Popup hidden");
    if (radarInstance) radarInstance.stop();
  } else {
    console.log("[Popup] Popup visible again");
    if (radarInstance && !radarInstance.animationFrame) {
      radarInstance.start();
    }
  }
});

console.log("[Popup] ✅ Script loaded and ready");