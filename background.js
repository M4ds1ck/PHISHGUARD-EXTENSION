// background.js - v3.0.0 with Privacy Consent & Advanced Threat Detection
console.log("=== 🌊 PhishGuard DeepSea v3.0 Starting ===");
const browserAPI = browser;

// ============================================
// PRIVACY & CONSENT MANAGEMENT
// ============================================
class ConsentManager {
  constructor() {
    this.consent = {
      apis: false,
      urlExpansion: false,
      lastUpdated: 0
    };
    this.CONSENT_DURATION = 30 * 24 * 60 * 60 * 1000; // 30 days
  }

  async load() {
    try {
      const data = await browserAPI.storage.local.get('consent');
      if (data.consent && Date.now() - data.consent.lastUpdated < this.CONSENT_DURATION) {
        this.consent = data.consent;
        console.log("[PhishGuard] Consent loaded:", this.consent);
      }
    } catch (err) {
      console.warn("[PhishGuard] Consent load failed:", err);
    }
  }

  async save() {
    this.consent.lastUpdated = Date.now();
    await browserAPI.storage.local.set({ consent: this.consent });
  }

  requiresConsent(action) {
    if (action === 'apis') return CONFIG.requireConsentForAPIs && !this.consent.apis;
    if (action === 'urlExpansion') return CONFIG.requireConsentForURLExpansion && !this.consent.urlExpansion;
    return false;
  }

  grant(action) {
    if (action === 'apis') this.consent.apis = true;
    if (action === 'urlExpansion') this.consent.urlExpansion = true;
    this.save();
  }
}

const consentManager = new ConsentManager();

// ============================================
// TYPOSQUATTING DETECTOR (Optimized)
// ============================================
class TyposquatDetector {
  constructor() {
    this.topDomains = [
      'google', 'facebook', 'youtube', 'instagram', 'twitter', 'linkedin',
      'microsoft', 'apple', 'amazon', 'netflix', 'tiktok', 'snapchat',
      'reddit', 'discord', 'telegram', 'whatsapp', 'zoom', 'dropbox',
      'github', 'stackoverflow', 'yahoo', 'bing', 'adobe', 'spotify',
      'twitch', 'pinterest', 'tumblr', 'medium', 'wordpress', 'slack',
      'paypal', 'stripe', 'square', 'venmo', 'chase', 'wellsfargo',
      'bankofamerica', 'citibank', 'capitalone', 'amex', 'discover',
      'coinbase', 'binance', 'kraken', 'robinhood', 'etrade', 'fidelity',
      'schwab', 'vanguard', 'wise', 'ebay', 'walmart', 'target', 'bestbuy',
      'aliexpress', 'etsy', 'shopify', 'wayfair', 'ikea', 'macys',
      'nordstrom', 'sephora', 'gamestop', 'newegg', 'overstock',
      'hulu', 'disneyplus', 'hbomax', 'paramount', 'peacock', 'espn',
      'crunchyroll', 'imdb', 'audible', 'kindle', 'steam', 'epicgames',
      'playstation', 'xbox', 'nintendo', 'roblox', 'minecraft', 'fortnite',
      'valorant', 'leagueoflegends', 'booking', 'expedia', 'airbnb',
      'uber', 'lyft', 'doordash', 'ubereats', 'grubhub', 'instacart',
      'fedex', 'ups', 'usps', 'dhl', 'cnn', 'bbc'
    ];
    this.domainSet = new Set(this.topDomains.map(d => d.toLowerCase()));
  }

  detect(hostname) {
    const domain = this.extractBase(hostname);
    if (this.domainSet.has(domain)) return null;

    let bestMatch = null;
    let bestScore = 0;
    const maxLength = domain.length + 3;
    const minLength = Math.max(3, domain.length - 3);

    for (const legit of this.topDomains) {
      if (legit.length > maxLength || legit.length < minLength) continue;
      
      const check = this.checkMatch(domain, legit.toLowerCase());
      if (check.score > bestScore) {
        bestScore = check.score;
        bestMatch = { ...check, target: legit };
      }
      if (check.score >= 95) break;
    }
    return bestMatch;
  }

  extractBase(hostname) {
    let clean = hostname.toLowerCase().replace(/^www\./, '');
    const parts = clean.split('.');
    return parts.length >= 2 ? parts[parts.length - 2] : clean;
  }

  checkMatch(domain, legit) {
    if (domain === legit) return { score: 0 };
    const distance = this.leven(domain, legit);

    if (distance === 1) {
      return { 
        score: 95, 
        method: 'Single character difference',
        detail: `"${domain}" vs "${legit}" (1 char off)` 
      };
    }
    if (distance === 2) {
      return { 
        score: 85, 
        method: 'Two character difference',
        detail: `"${domain}" vs "${legit}" (2 chars off)` 
      };
    }
    if (domain.includes(legit) && domain !== legit) {
      return { 
        score: 80, 
        method: 'Brand name with additions',
        detail: `Contains "${legit}" with extra text` 
      };
    }
    if (legit.includes(domain) && domain.length >= 4) {
      return { 
        score: 70, 
        method: 'Shortened brand name',
        detail: `Looks like shortened "${legit}"` 
      };
    }
    if (this.hasHomoglyphs(domain, legit)) {
      return { 
        score: 90, 
        method: 'Look-alike characters',
        detail: `Uses confusing characters to mimic "${legit}"` 
      };
    }
    return { score: 0 };
  }

  hasHomoglyphs(domain, legit) {
    const subs = { 
      'o':'0','0':'o','i':'1','1':'i','l':'i','a':'@','@':'a',
      's':'5','5':'s','e':'3','3':'e','g':'9','9':'g','b':'6','6':'b'
    };
    let n1 = domain, n2 = legit;
    for (const [from, to] of Object.entries(subs)) {
      n1 = n1.replace(new RegExp(from, 'g'), to);
      n2 = n2.replace(new RegExp(from, 'g'), to);
    }
    return n1 === n2 && domain !== legit;
  }

  leven(a, b) {
    if (a === b) return 0;
    if (a.length === 0) return b.length;
    if (b.length === 0) return a.length;
    if (a.length > b.length) [a, b] = [b, a];

    const matrix = [];
    for (let i = 0; i <= b.length; i++) matrix[i] = [i];
    for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        const cost = a[j - 1] === b[i - 1] ? 0 : 1;
        matrix[i][j] = Math.min(
          matrix[i - 1][j] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j - 1] + cost
        );
      }
    }
    return matrix[b.length][a.length];
  }
}

const typoDetector = new TyposquatDetector();

// ============================================
// CONFIGURATION
// ============================================
let CONFIG = {
  VERSION: "3.0.0",
  BLOCK_THRESHOLD: 50,
  BYPASS_DURATION: 5 * 60 * 1000, // 5 minutes
  DEBUG: false,
  PROTECTION_ENABLED: true,
  BLOCKING_ENABLED: true,
  NOTIFICATIONS_ENABLED: true,
  AUTO_SCAN_ENABLED: true,
  requireConsentForAPIs: true,
  requireConsentForURLExpansion: true,
  CACHE_DURATION: 5 * 60 * 1000, // 5 minutes
  MAX_CACHE_SIZE: 200
};

let whitelist = new Set();
let blacklist = new Set();
let temporaryBypasses = new Map();
let stats = { sitesScanned: 0, threatsBlocked: 0, bypassesUsed: 0, consentsGranted: 0 };
let isInitialized = false;
let statsSavePending = false;
let analysisCache = new Map();

// Legitimate domains (fast path)
const LEGITIMATE = new Set([
  'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
  'linkedin.com', 'github.com', 'stackoverflow.com', 'reddit.com', 'amazon.com',
  'microsoft.com', 'apple.com', 'netflix.com', 'paypal.com', 'ebay.com',
  'wikipedia.org', 'mozilla.org', 'duckduckgo.com', 'bing.com'
]);

// ============================================
// LOGGING SYSTEM
// ============================================
const Logger = {
  debug: (...args) => CONFIG.DEBUG && console.log("[PhishGuard DEBUG]", ...args),
  info: (...args) => console.log("[PhishGuard INFO]", ...args),
  warn: (...args) => console.warn("[PhishGuard WARN]", ...args),
  error: (...args) => console.error("[PhishGuard ERROR]", ...args)
};

// ============================================
// INITIALIZATION
// ============================================
async function init() {
  if (isInitialized) return;
  Logger.info("Initializing...");
  
  try {
    // Load consent first
    await consentManager.load();
    
    // Load settings
    const data = await browserAPI.storage.local.get(['whitelist', 'blacklist', 'stats', 'settings']);
    
    if (data.whitelist) whitelist = new Set(data.whitelist);
    if (data.blacklist) blacklist = new Set(data.blacklist);
    if (data.stats) stats = data.stats;
    
    if (data.settings) {
      CONFIG.BLOCK_THRESHOLD = data.settings.blockThreshold || 50;
      CONFIG.PROTECTION_ENABLED = data.settings.protectionEnabled !== false;
      CONFIG.BLOCKING_ENABLED = data.settings.blockingEnabled !== false;
      CONFIG.NOTIFICATIONS_ENABLED = data.settings.notificationsEnabled !== false;
      CONFIG.AUTO_SCAN_ENABLED = data.settings.autoScanEnabled !== false;
      CONFIG.requireConsentForAPIs = data.settings.requireConsentForAPIs !== false;
      CONFIG.requireConsentForURLExpansion = data.settings.requireConsentForURLExpansion !== false;
      Logger.info("Settings loaded:", {
        threshold: CONFIG.BLOCK_THRESHOLD,
        protection: CONFIG.PROTECTION_ENABLED,
        consentAPIs: CONFIG.requireConsentForAPIs,
        consentExpansion: CONFIG.requireConsentForURLExpansion
      });
    }
    
    isInitialized = true;
    Logger.info("✅ Initialization complete");
  } catch (err) {
    Logger.error("Init failed:", err);
  }
}

browserAPI.runtime.onStartup.addListener(init);
browserAPI.runtime.onInstalled.addListener(init);
init();

// ============================================
// CACHE MANAGEMENT
// ============================================
function cleanupCache() {
  const now = Date.now();
  let cleaned = 0;
  
  // Clean bypasses
  for (const [url, time] of temporaryBypasses.entries()) {
    if (now - time > CONFIG.BYPASS_DURATION) {
      temporaryBypasses.delete(url);
      cleaned++;
    }
  }

  // Clean analysis cache
  for (const [url, value] of analysisCache.entries()) {
    if (now - value.timestamp > CONFIG.CACHE_DURATION) {
      analysisCache.delete(url);
      cleaned++;
    }
  }

  // Enforce max size
  if (analysisCache.size > CONFIG.MAX_CACHE_SIZE) {
    const urls = Array.from(analysisCache.keys()).sort((a, b) => 
      analysisCache.get(b).timestamp - analysisCache.get(a).timestamp
    ).slice(CONFIG.MAX_CACHE_SIZE);
    
    urls.forEach(url => analysisCache.delete(url));
    cleaned += urls.length;
  }

  if (cleaned > 0) {
    Logger.debug(`🧹 Cleaned ${cleaned} cache entries`);
  }
}

// Run cleanup every minute
setInterval(cleanupCache, 60000);

// ============================================
// NOTIFICATIONS
// ============================================
function showNotification(title, message, priority = 0) {
  if (!CONFIG.NOTIFICATIONS_ENABLED) return;
  try {
    browserAPI.notifications.create({
      type: 'basic',
      iconUrl: browserAPI.runtime.getURL('icons/icon128.png'),
      title: title,
      message: message,
      priority: priority
    });
  } catch (err) {
    Logger.error("Notification failed:", err);
  }
}

// ============================================
// STATS MANAGEMENT
// ============================================
async function saveStats() {
  if (statsSavePending) return;
  statsSavePending = true;
  
  setTimeout(async () => {
    try {
      await browserAPI.storage.local.set({ stats });
      Logger.debug("💾 Stats saved");
    } catch (err) {
      Logger.error("Stats save failed:", err);
    } finally {
      statsSavePending = false;
    }
  }, 500);
}

// ============================================
// URL EXPANSION (Privacy-Protected)
// ============================================
async function expandShortURL(url) {
  // Check consent first
  if (consentManager.requiresConsent('urlExpansion')) {
    Logger.warn("URL expansion blocked - consent required");
    return { expanded: url, isShortener: false, consentRequired: true };
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);
    
    const response = await fetch(url, {
      method: 'HEAD',
      redirect: 'follow',
      signal: controller.signal,
      mode: 'no-cors' // Prevent CORS issues
    });
    
    clearTimeout(timeout);
    
    if (response.redirected && response.url !== url) {
      Logger.info(`🔗 Expanded ${url} → ${response.url}`);
      return { 
        expanded: response.url, 
        isShortener: true,
        original: url 
      };
    }
  } catch (error) {
    Logger.warn("URL expansion failed:", error.message);
  }
  
  return { expanded: url, isShortener: false };
}

// ============================================
// ANALYSIS ENGINE (Enhanced)
// ============================================
function analyzeURL(url) {
  if (!CONFIG.PROTECTION_ENABLED) {
    return { score: 0, reasons: [], disabled: true };
  }

  // Check cache first
  const cached = analysisCache.get(url);
  if (cached && Date.now() - cached.timestamp < CONFIG.CACHE_DURATION) {
    Logger.debug("Using cached analysis for:", url);
    return cached.result;
  }

  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();
    const protocol = urlObj.protocol;
    let score = 0;
    let reasons = [];

    // System pages - always safe
    if (url.startsWith('about:') || url.startsWith('moz-extension:') || 
        url.startsWith('chrome:') || url.startsWith('edge:') || 
        url.startsWith('file:')) {
      return { score: 0, reasons: [], systemPage: true };
    }

    // Legitimate sites check
    if (isLegitimate(hostname)) {
      if (protocol === 'http:') {
        return { 
          score: 10, 
          reasons: [{ reason: "Legitimate site using insecure HTTP", weight: 10 }], 
          legitimate: true 
        };
      }
      return { score: 0, reasons: [], legitimate: true };
    }

    // User lists
    if (whitelist.has(hostname)) {
      return { score: 0, reasons: [], whitelisted: true };
    }
    if (blacklist.has(hostname)) {
      return { 
        score: 100, 
        reasons: [{ reason: "🚫 Blocked by user", weight: 100 }], 
        blacklisted: true 
      };
    }

    // Temporary bypass
    if (temporaryBypasses.has(url)) {
      const time = temporaryBypasses.get(url);
      if (Date.now() - time < CONFIG.BYPASS_DURATION) {
        return { score: 0, reasons: [], bypassed: true };
      }
      temporaryBypasses.delete(url);
    }

    // Critical checks first
    if (protocol === 'http:') {
      score += 15;
      reasons.push({ 
        reason: "Unencrypted HTTP Connection", 
        weight: 15,
        detail: "Site doesn't use HTTPS encryption",
        category: 'protocol'
      });

      // Check for password fields (would be detected by content script)
      // This is a placeholder - actual detection happens in content script
    }

    // IP address access
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
      score += 40;
      reasons.push({ 
        reason: "Direct IP Address Access", 
        weight: 40,
        detail: "Using IP address instead of domain name",
        category: 'ip_address'
      });
    }

    // Typosquatting detection
    const typoResult = typoDetector.detect(hostname);
    if (typoResult && typoResult.score > 0) {
      const weight = Math.min(95, Math.round(typoResult.score * 0.6));
      score += weight;
      reasons.push({
        reason: `⚠️ Impersonates "${typoResult.target}" - ${typoResult.method}`,
        weight: weight,
        detail: typoResult.detail,
        category: 'typosquatting'
      });
    }

    // Suspicious TLD
    const tld = hostname.split('.').pop();
    const badTLDs = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'click', 'link', 'icu', 'pw', 'ga', 'cf'];
    if (badTLDs.includes(tld)) {
      score += 25;
      reasons.push({ 
        reason: `Suspicious TLD (.${tld})`, 
        weight: 25,
        detail: `.${tld} domains are frequently used in phishing campaigns`,
        category: 'tld'
      });
    }

    // IDN Homograph attack
    if (hostname.match(/[^\x00-\x7F]/)) {
      score += 30;
      reasons.push({ 
        reason: "⚠️ International Domain Name (IDN)", 
        weight: 30,
        detail: "May contain look-alike characters from different alphabets (homograph attack)",
        category: 'idn'
      });
    }

    // Domain structure analysis
    const parts = hostname.split('.');
    if (parts.length > 4) {
      score += 15;
      reasons.push({ 
        reason: `Too many subdomains (${parts.length})`, 
        weight: 15,
        detail: "Excessive subdomains often indicate phishing",
        category: 'subdomains'
      });
    }

    if (hostname.length > 40) {
      score += 10;
      reasons.push({ 
        reason: "Very long domain name", 
        weight: 10,
        detail: `${hostname.length} characters`,
        category: 'length'
      });
    }

    const dashCount = (hostname.match(/-/g) || []).length;
    if (dashCount > 2) {
      score += 10;
      reasons.push({ 
        reason: `Too many dashes (${dashCount})`, 
        weight: 10,
        detail: "Excessive dashes in domain name",
        category: 'dashes'
      });
    }

    if (hostname.includes('_')) {
      score += 10;
      reasons.push({ 
        reason: "Domain contains underscores", 
        weight: 10,
        detail: "Legitimate domains rarely use underscores",
        category: 'underscores'
      });
    }

    // Suspicious keywords
    const keywords = ['login', 'signin', 'verify', 'account', 'secure', 'update', 'banking', 'password'];
    const lowerHost = hostname.toLowerCase();
    for (const keyword of keywords) {
      if (lowerHost.includes(keyword)) {
        score += 15;
        reasons.push({ 
          reason: `Suspicious keyword: ${keyword}`, 
          weight: 15,
          detail: `Domain contains high-risk keyword "${keyword}"`,
          category: 'keywords'
        });
        break; // Only count once
      }
    }

    // Non-standard ports
    if (urlObj.port && !['80', '443', ''].includes(urlObj.port)) {
      const portNum = parseInt(urlObj.port);
      if (portNum < 1024 || portNum > 49151) {
        score += 15;
        reasons.push({ 
          reason: `Non-standard port (${urlObj.port})`, 
          weight: 15,
          detail: "Unusual port number for web traffic",
          category: 'port'
        });
      }
    }

    // URL shortener detection (without expansion if no consent)
    const shorteners = new Set([
      'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
      'buff.ly', 'adf.ly', 'bl.ink', 'lnkd.in', 'shorte.st', 'mcaf.ee'
    ]);
    
    let isShortener = false;
    for (const shortener of shorteners) {
      if (hostname.includes(shortener)) {
        isShortener = true;
        break;
      }
    }
    
    if (isShortener) {
      score += 20;
      reasons.push({ 
        reason: "URL Shortener Service", 
        weight: 20,
        detail: "Shortened URLs can hide malicious destinations",
        category: 'url_shortener',
        consentRequired: consentManager.requiresConsent('urlExpansion')
      });
    }

    // Cap score at 100
    score = Math.min(score, 100);

    const result = { 
      score: score, 
      reasons: reasons, 
      hostname: hostname,
      protocol: protocol
    };
    
    // Cache the result
    analysisCache.set(url, {
      result: result,
      timestamp: Date.now()
    });
    
    return result;
  } catch (err) {
    Logger.error("Analysis failed for", url, ":", err);
    return { score: 0, reasons: [], error: err.message };
  }
}

function isLegitimate(hostname) {
  const lower = hostname.toLowerCase();
  if (LEGITIMATE.has(lower)) return true;
  if (lower.startsWith('www.') && LEGITIMATE.has(lower.substring(4))) return true;
  for (const domain of LEGITIMATE) {
    if (lower.endsWith('.' + domain)) return true;
  }
  return false;
}

// ============================================
// MESSAGE HANDLER
// ============================================
browserAPI.runtime.onMessage.addListener((request, sender, sendResponse) => {
  Logger.debug("📨 Message received:", request.action);

  // Handle synchronous messages immediately
  if (request.action === "getStats") {
    sendResponse(stats);
    return false;
  }

  if (request.action === "getConsentStatus") {
    sendResponse({
      apis: consentManager.consent.apis,
      urlExpansion: consentManager.consent.urlExpansion,
      requiresAPIs: CONFIG.requireConsentForAPIs,
      requiresExpansion: CONFIG.requireConsentForURLExpansion
    });
    return false;
  }

  if (request.action === "grantConsent") {
    if (request.type === 'apis') consentManager.grant('apis');
    if (request.type === 'urlExpansion') consentManager.grant('urlExpansion');
    stats.consentsGranted++;
    saveStats();
    sendResponse({ success: true });
    return false;
  }

  if (request.action === "updateSettings") {
    if (request.settings) {
      CONFIG.BLOCK_THRESHOLD = request.settings.blockThreshold || 50;
      CONFIG.PROTECTION_ENABLED = request.settings.protectionEnabled !== false;
      CONFIG.BLOCKING_ENABLED = request.settings.blockingEnabled !== false;
      CONFIG.NOTIFICATIONS_ENABLED = request.settings.notificationsEnabled !== false;
      CONFIG.AUTO_SCAN_ENABLED = request.settings.autoScanEnabled !== false;
      CONFIG.requireConsentForAPIs = request.settings.requireConsentForAPIs !== false;
      CONFIG.requireConsentForURLExpansion = request.settings.requireConsentForURLExpansion !== false;
      
      Logger.info("✅ Settings updated");
      sendResponse({ success: true });
    }
    return false;
  }

  // Handle async messages
  (async () => {
    try {
      if (request.action === "analyzeUrl") {
        const url = request.url;
        const forceAnalysis = request.forceAnalysis || false;
        
        // Validate URL
        if (!url || typeof url !== 'string') {
          sendResponse({ score: 0, reasons: [], error: "Invalid URL", system: true });
          return;
        }
        
        // Skip system pages
        if (url.startsWith('about:') || url.startsWith('moz-extension:') || 
            url.startsWith('chrome:') || url.startsWith('edge:')) {
          sendResponse({ score: 0, reasons: [], system: true });
          return;
        }

        // Validate URL format
        try {
          new URL(url);
        } catch (e) {
          Logger.warn("Invalid URL format:", url);
          sendResponse({ score: 0, reasons: [], error: "Invalid URL format", system: true });
          return;
        }

        // Force analysis ignores bypass
        if (!forceAnalysis && temporaryBypasses.has(url)) {
          const time = temporaryBypasses.get(url);
          if (Date.now() - time < CONFIG.BYPASS_DURATION) {
            const result = analyzeURL(url);
            result.bypassed = true;
            sendResponse(result);
            return;
          }
          temporaryBypasses.delete(url);
        }

        const result = analyzeURL(url);
        
        // Track stats
        if (!result.systemPage && !result.whitelisted && !result.legitimate) {
          stats.sitesScanned++;
          if (result.score >= CONFIG.BLOCK_THRESHOLD) {
            stats.threatsBlocked++;
          }
          saveStats();
        }
        
        sendResponse(result);
        return;
      }

      if (request.action === "setTemporaryBypass") {
        temporaryBypasses.set(request.url, Date.now());
        stats.bypassesUsed++;
        saveStats();
        Logger.info("⏰ Bypass set for", request.url);
        sendResponse({ success: true, timestamp: Date.now() });
        return;
      }

      if (request.action === "addToWhitelist") {
        const domain = request.domain.toLowerCase();
        whitelist.add(domain);
        await browserAPI.storage.local.set({ whitelist: Array.from(whitelist) });
        Logger.info("✅ Whitelisted:", domain);
        
        // Clear cache for this domain
        for (const [url] of analysisCache.entries()) {
          try {
            if (new URL(url).hostname.toLowerCase() === domain) {
              analysisCache.delete(url);
            }
          } catch (e) {}
        }
        
        sendResponse({ success: true });
        return;
      }

      if (request.action === "addToBlacklist") {
        const domain = request.domain.toLowerCase();
        blacklist.add(domain);
        stats.threatsBlocked++;
        await browserAPI.storage.local.set({ 
          blacklist: Array.from(blacklist),
          stats: stats 
        });
        Logger.info("🚫 Blacklisted:", domain);
        
        // Clear cache and bypass
        for (const [url] of analysisCache.entries()) {
          try {
            if (new URL(url).hostname.toLowerCase() === domain) {
              analysisCache.delete(url);
              temporaryBypasses.delete(url);
            }
          } catch (e) {}
        }
        
        sendResponse({ success: true });
        return;
      }

      if (request.action === "expandURL") {
        // This is called from content script with user consent
        const result = await expandShortURL(request.url);
        sendResponse(result);
        return;
      }

      sendResponse({ error: "Unknown action" });
    } catch (err) {
      Logger.error("Message handler error:", err);
      sendResponse({ error: err.message });
    }
  })();

  return true; // Indicates async response
});

// ============================================
// TAB MONITORING
// ============================================
let tabUpdateTimers = new Map();

browserAPI.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (!changeInfo.url || changeInfo.status !== 'loading') return;
  if (!CONFIG.AUTO_SCAN_ENABLED) return;
  
  const url = changeInfo.url;
  if (url.startsWith('about:') || url.startsWith('moz-extension:')) return;

  // Debounce rapid updates
  if (tabUpdateTimers.has(tabId)) {
    clearTimeout(tabUpdateTimers.get(tabId));
  }

  tabUpdateTimers.set(tabId, setTimeout(() => {
    processTabUpdate(tabId, url);
    tabUpdateTimers.delete(tabId);
  }, 150));
});

function processTabUpdate(tabId, url) {
  try {
    // Skip if bypass is active
    if (temporaryBypasses.has(url)) {
      const time = temporaryBypasses.get(url);
      if (Date.now() - time < CONFIG.BYPASS_DURATION) {
        // Set safe badge
        browserAPI.browserAction.setBadgeText({ text: "", tabId: tabId });
        return;
      }
      temporaryBypasses.delete(url);
    }

    const analysis = analyzeURL(url);
    
    // Update badge
    let badgeText = "";
    let badgeColor = "#4caf50"; // Green

    if (analysis.score >= 75) {
      badgeText = "!!!";
      badgeColor = "#ff0000"; // Red
    } else if (analysis.score >= 50) {
      badgeText = "!!";
      badgeColor = "#ff003c"; // Dark red
    } else if (analysis.score >= 20) {
      badgeText = "!";
      badgeColor = "#ffb300"; // Orange
    }

    browserAPI.browserAction.setBadgeText({ text: badgeText, tabId: tabId });
    browserAPI.browserAction.setBadgeBackgroundColor({ color: badgeColor, tabId: tabId });

    // Block if needed
    if (CONFIG.BLOCKING_ENABLED && analysis.score >= CONFIG.BLOCK_THRESHOLD) {
      Logger.info("🚫 BLOCKING:", url, "Score:", analysis.score);
      
      // Show notification
      if (CONFIG.NOTIFICATIONS_ENABLED) {
        showNotification(
          "🛡️ Threat Blocked",
          `PhishGuard blocked ${analysis.hostname} (Score: ${analysis.score})`,
          2
        );
      }

      try {
        const warningUrl = browserAPI.runtime.getURL('warning.html') +
          `?url=${encodeURIComponent(url)}` +
          `&score=${analysis.score}` +
          `&reasons=${encodeURIComponent(JSON.stringify(analysis.reasons))}`;

        browserAPI.tabs.update(tabId, { url: warningUrl }).catch(err => {
          Logger.error("Failed to redirect to warning page:", err);
        });
      } catch (err) {
        Logger.error("Error creating warning URL:", err);
      }
    } else if (analysis.score >= 50 && CONFIG.NOTIFICATIONS_ENABLED) {
      // High risk but not blocked - notify
      showNotification(
        "⚠️ High Risk Site Detected",
        `${analysis.hostname} has a threat score of ${analysis.score}`,
        1
      );
    }
  } catch (err) {
    Logger.error("Tab processing error:", err);
    // Set neutral badge on error
    try {
      browserAPI.browserAction.setBadgeText({ text: "", tabId: tabId });
      browserAPI.browserAction.setBadgeBackgroundColor({ color: "#9e9e9e", tabId: tabId });
    } catch (e) {}
  }
}

// Cleanup on suspend
browserAPI.runtime.onSuspend.addListener(() => {
  tabUpdateTimers.forEach(timer => clearTimeout(timer));
  tabUpdateTimers.clear();
});

Logger.info("=== ✅ PhishGuard DeepSea v3.0 Ready ===");
Logger.info("🎯 Brands monitored:", typoDetector.topDomains.length);
Logger.info("⚙️ Block threshold:", CONFIG.BLOCK_THRESHOLD);
Logger.info("🔔 Notifications:", CONFIG.NOTIFICATIONS_ENABLED ? "ON" : "OFF");
Logger.info("🛡️ Privacy consent required for APIs:", CONFIG.requireConsentForAPIs);
Logger.info("🔗 Privacy consent required for URL expansion:", CONFIG.requireConsentForURLExpansion);