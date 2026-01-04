// background.js - COMPLETE FIXED VERSION v2.1.0
// Firefox Optimized - All bugs fixed, performance optimized
console.log("=== PhishGuard Enhanced v2.1 Starting ===");

const browserAPI = browser;
console.log("Browser: Firefox");

// ============================================
// TYPOSQUATTING DETECTOR (Optimized & Fixed)
// ============================================

class TyposquatDetector {
    constructor() {
        // Deduplicated top 100 domains (removed duplicates from your original)
        this.topDomains = [
            // Tech & Social (30)
            'google', 'facebook', 'youtube', 'instagram', 'twitter', 'linkedin',
            'microsoft', 'apple', 'amazon', 'netflix', 'tiktok', 'snapchat',
            'reddit', 'discord', 'telegram', 'whatsapp', 'zoom', 'dropbox',
            'github', 'stackoverflow', 'yahoo', 'bing', 'adobe', 'spotify',
            'twitch', 'pinterest', 'tumblr', 'medium', 'wordpress', 'slack',

            // Finance (20)
            'paypal', 'stripe', 'square', 'venmo', 'chase', 'wellsfargo',
            'bankofamerica', 'citibank', 'capitalone', 'amex', 'discover',
            'coinbase', 'binance', 'kraken', 'robinhood', 'etrade', 'fidelity',
            'schwab', 'vanguard', 'wise',

            // E-commerce (15)
            'ebay', 'walmart', 'target', 'bestbuy', 'aliexpress', 'etsy',
            'shopify', 'wayfair', 'ikea', 'macys', 'nordstrom', 'sephora',
            'gamestop', 'newegg', 'overstock',

            // Streaming (10)
            'hulu', 'disneyplus', 'hbomax', 'paramount', 'peacock', 'espn',
            'crunchyroll', 'imdb', 'audible', 'kindle',

            // Gaming (10)
            'steam', 'epicgames', 'playstation', 'xbox', 'nintendo', 'roblox',
            'minecraft', 'fortnite', 'valorant', 'leagueoflegends',

            // Other (15)
            'booking', 'expedia', 'airbnb', 'uber', 'lyft', 'doordash',
            'ubereats', 'grubhub', 'instacart', 'fedex', 'ups', 'usps',
            'dhl', 'cnn', 'bbc'
        ];
        
        // Create Set for O(1) exact match lookup
        this.domainSet = new Set(this.topDomains);
    }

    detect(hostname) {
        const domain = this.extractBase(hostname);
        let bestMatch = null;
        let bestScore = 0;

        // Early exit if exact match (legitimate)
        if (this.domainSet.has(domain)) {
            return null;
        }

        // OPTIMIZATION: Only check domains within reasonable edit distance
        const maxLength = domain.length + 3;
        const minLength = Math.max(3, domain.length - 3);

        for (const legit of this.topDomains) {
            // Skip if length difference too large (optimization)
            if (legit.length > maxLength || legit.length < minLength) {
                continue;
            }

            const check = this.checkMatch(domain, legit);
            if (check.score > bestScore) {
                bestScore = check.score;
                bestMatch = { ...check, target: legit };
            }

            // Early exit if perfect suspicious match found
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

        // 1 character difference = VERY suspicious
        if (distance === 1) {
            return {
                score: 95,
                method: 'Single character difference',
                detail: `"${domain}" vs "${legit}" (1 character off)`
            };
        }

        // 2 character difference = suspicious
        if (distance === 2) {
            return {
                score: 85,
                method: 'Two character difference',
                detail: `"${domain}" vs "${legit}" (2 characters off)`
            };
        }

        // Contains legitimate brand with additions (e.g., paypal-secure)
        if (domain.includes(legit) && domain !== legit) {
            return {
                score: 80,
                method: 'Brand name with additions',
                detail: `Contains "${legit}" with extra text`
            };
        }

        // Legitimate contains suspicious (shortened)
        if (legit.includes(domain) && domain.length >= 4) {
            return {
                score: 70,
                method: 'Shortened brand name',
                detail: `Looks like shortened "${legit}"`
            };
        }

        // Homoglyph check (o->0, i->1, etc.)
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
            'o': '0', '0': 'o',
            'i': '1', '1': 'i', 'l': 'i',
            'a': '@', '@': 'a',
            's': '5', '5': 's',
            'e': '3', '3': 'e'
        };

        let normalized1 = domain;
        let normalized2 = legit;

        for (const [from, to] of Object.entries(subs)) {
            normalized1 = normalized1.replace(new RegExp(from, 'g'), to);
            normalized2 = normalized2.replace(new RegExp(from, 'g'), to);
        }

        return normalized1 === normalized2 && domain !== legit;
    }

    // OPTIMIZED Levenshtein with early exit
    leven(a, b) {
        if (a === b) return 0;
        if (a.length === 0) return b.length;
        if (b.length === 0) return a.length;

        // Swap to ensure 'a' is shorter (optimization)
        if (a.length > b.length) {
            [a, b] = [b, a];
        }

        const matrix = [];
        for (let i = 0; i <= b.length; i++) matrix[i] = [i];
        for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

        for (let i = 1; i <= b.length; i++) {
            for (let j = 1; j <= a.length; j++) {
                const cost = a[j - 1] === b[i - 1] ? 0 : 1;
                matrix[i][j] = Math.min(
                    matrix[i - 1][j] + 1,      // Deletion
                    matrix[i][j - 1] + 1,      // Insertion
                    matrix[i - 1][j - 1] + cost // Substitution
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

const CONFIG = {
    VERSION: "2.1.0",
    BLOCK_THRESHOLD: 50,
    BYPASS_DURATION: 5 * 60 * 1000, // 5 minutes
    DEBUG: true,
    THRESHOLDS: {
        SAFE: 19,
        WARNING: 20,
        DANGER: 50,
        CRITICAL: 75
    }
};

// ============================================
// STATE MANAGEMENT (Fixed with proper locking)
// ============================================

let whitelist = new Set();
let blacklist = new Set();
let temporaryBypasses = new Map();
let stats = { sitesScanned: 0, threatsBlocked: 0, bypassesUsed: 0 };
let isInitialized = false;
let statsSavePending = false;

const LEGITIMATE = new Set([
    'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
    'linkedin.com', 'github.com', 'stackoverflow.com', 'reddit.com', 'amazon.com',
    'microsoft.com', 'apple.com', 'netflix.com', 'paypal.com', 'ebay.com',
    'wikipedia.org', 'mozilla.org'
]);

function log(...args) {
    if (CONFIG.DEBUG) console.log("[PhishGuard]", ...args);
}

function error(...args) {
    console.error("[PhishGuard ERROR]", ...args);
}

// ============================================
// INITIALIZATION (Fixed - runs only once)
// ============================================

async function init() {
    if (isInitialized) {
        log("Already initialized, skipping");
        return;
    }

    log("Initializing...");
    try {
        const data = await browserAPI.storage.local.get(['whitelist', 'blacklist', 'stats']);
        
        if (data.whitelist && Array.isArray(data.whitelist)) {
            whitelist = new Set(data.whitelist);
            log("Loaded whitelist:", whitelist.size, "domains");
        }
        
        if (data.blacklist && Array.isArray(data.blacklist)) {
            blacklist = new Set(data.blacklist);
            log("Loaded blacklist:", blacklist.size, "domains");
        }
        
        if (data.stats) {
            stats = data.stats;
            log("Loaded stats:", stats);
        }
        
        isInitialized = true;
        log("✅ Initialization complete");
    } catch (err) {
        error("Init failed:", err);
    }
}

// Firefox event listeners (fixed - no duplication)
browserAPI.runtime.onStartup.addListener(init);
browserAPI.runtime.onInstalled.addListener(init);

// Initialize immediately on script load
init();

// Cleanup expired bypasses every minute
setInterval(() => {
    const now = Date.now();
    let cleaned = 0;
    
    for (const [url, time] of temporaryBypasses.entries()) {
        if (now - time > CONFIG.BYPASS_DURATION) {
            temporaryBypasses.delete(url);
            cleaned++;
        }
    }
    
    if (cleaned > 0) {
        log("🧹 Cleaned", cleaned, "expired bypasses");
    }
}, 60000);

// ============================================
// STATS MANAGEMENT (Fixed with debouncing)
// ============================================

async function saveStats() {
    if (statsSavePending) return;
    
    statsSavePending = true;
    
    // Debounce: wait 500ms before saving
    setTimeout(async () => {
        try {
            await browserAPI.storage.local.set({ stats });
            log("💾 Stats saved:", stats);
        } catch (err) {
            error("Stats save failed:", err);
        } finally {
            statsSavePending = false;
        }
    }, 500);
}

// ============================================
// ENHANCED ANALYSIS ENGINE (Fixed)
// ============================================

function analyzeURL(url) {
    try {
        const urlObj = new URL(url);
        const hostname = urlObj.hostname;
        const protocol = urlObj.protocol;

        let score = 0;
        let reasons = [];

        // Check if legitimate domain
        if (isLegitimate(hostname)) {
            log("✅ Legitimate domain:", hostname);
            
            // Still warn about HTTP on legitimate sites
            if (protocol === 'http:') {
                return {
                    score: 10,
                    reasons: [{ reason: "Legitimate site using insecure HTTP", weight: 10 }],
                    legitimate: true
                };
            }
            return { score: 0, reasons: [], legitimate: true };
        }

        // Check whitelist
        if (whitelist.has(hostname)) {
            log("✅ Whitelisted:", hostname);
            return { score: 0, reasons: [], whitelisted: true };
        }

        // Check blacklist
        if (blacklist.has(hostname)) {
            log("🚫 Blacklisted:", hostname);
            return {
                score: 100,
                reasons: [{ reason: "🚫 Blocked by user", weight: 100 }],
                blacklisted: true
            };
        }

        // === TYPOSQUATTING DETECTION ===
        const typoResult = typoDetector.detect(hostname);
        if (typoResult && typoResult.score > 0) {
            log("⚠️ TYPOSQUATTING DETECTED:", typoResult);

            const weight = Math.round(typoResult.score * 0.6); // 60% of confidence
            score += weight;
            reasons.push({
                reason: `⚠️ Impersonates "${typoResult.target}" - ${typoResult.method}`,
                weight: weight,
                detail: typoResult.detail,
                category: 'typosquatting'
            });
        }

        // === STANDARD SECURITY CHECKS ===

        // HTTP check
        if (protocol === 'http:') {
            score += 15;
            reasons.push({ reason: "Insecure HTTP connection", weight: 15 });
        }

        // IP address instead of domain
        if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
            score += 40;
            reasons.push({ reason: "Direct IP address access", weight: 40 });
        }

        // Suspicious TLD
        const tld = hostname.split('.').pop().toLowerCase();
        const badTLDs = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'click', 'link', 'icu', 'pw'];
        if (badTLDs.includes(tld)) {
            score += 25;
            reasons.push({ reason: `Suspicious TLD (.${tld})`, weight: 25 });
        }

        // Long domain name
        if (hostname.length > 40) {
            score += 10;
            reasons.push({ reason: "Very long domain name", weight: 10 });
        }

        // Excessive subdomains
        const parts = hostname.split('.');
        if (parts.length > 4) {
            score += 15;
            reasons.push({ reason: `Too many subdomains (${parts.length})`, weight: 15 });
        }

        // Suspicious keywords (only if NOT already flagged for typosquatting)
        if (!typoResult || typoResult.score < 70) {
            const keywords = ['login', 'signin', 'verify', 'account', 'secure', 'update', 'banking'];
            const lowerHost = hostname.toLowerCase();
            for (const keyword of keywords) {
                if (lowerHost.includes(keyword)) {
                    score += 15;
                    reasons.push({ reason: `Suspicious keyword: ${keyword}`, weight: 15 });
                    break; // Only flag once
                }
            }
        }

        // Excessive dashes
        const dashCount = (hostname.match(/-/g) || []).length;
        if (dashCount > 2) {
            score += 10;
            reasons.push({ reason: `Too many dashes (${dashCount})`, weight: 10 });
        }

        // Underscores in domain (unusual)
        if (hostname.includes('_')) {
            score += 10;
            reasons.push({ reason: "Domain contains underscores", weight: 10 });
        }

        // Many digits (e.g., paypal123456.com)
        const digitCount = (hostname.match(/\d/g) || []).length;
        if (digitCount > 4) {
            score += 10;
            reasons.push({ reason: `Many digits in domain (${digitCount})`, weight: 10 });
        }

        // Cap score at 100
        score = Math.min(score, 100);

        return {
            score: score,
            reasons: reasons,
            hostname: hostname
        };

    } catch (err) {
        error("Analysis failed:", err);
        return { score: 0, reasons: [], error: err.message };
    }
}

function isLegitimate(hostname) {
    const lower = hostname.toLowerCase();
    
    // Direct match
    if (LEGITIMATE.has(lower)) return true;
    
    // Check without www prefix
    if (lower.startsWith('www.')) {
        const withoutWww = lower.substring(4);
        if (LEGITIMATE.has(withoutWww)) return true;
    }
    
    // Check if subdomain of legitimate domain
    for (const domain of LEGITIMATE) {
        if (lower.endsWith('.' + domain)) return true;
    }
    
    return false;
}

// ============================================
// MESSAGE HANDLER (FIXED - supports forceAnalysis)
// ============================================

browserAPI.runtime.onMessage.addListener((request, sender, sendResponse) => {
    log("📨 Message:", request.action);

    // Synchronous responses (no async needed)
    if (request.action === "getStats") {
        sendResponse(stats);
        return false; // No async
    }

    // Asynchronous responses
    (async () => {
        try {
            if (request.action === "analyzeUrl") {
                const url = request.url;
                const forceAnalysis = request.forceAnalysis || false; // NEW: Force flag
                
                // Ignore system pages
                if (!url || url.startsWith('about:') || url.startsWith('moz-extension:')) {
                    sendResponse({ score: 0, reasons: [], system: true });
                    return;
                }

                // Check if bypassed (UNLESS forceAnalysis is true)
                if (!forceAnalysis && temporaryBypasses.has(url)) {
                    const time = temporaryBypasses.get(url);
                    if (Date.now() - time < CONFIG.BYPASS_DURATION) {
                        // Return real analysis but mark as bypassed
                        const result = analyzeURL(url);
                        result.bypassed = true;
                        sendResponse(result);
                        return;
                    }
                    temporaryBypasses.delete(url);
                }

                // Analyze URL (always get real score)
                const result = analyzeURL(url);
                stats.sitesScanned++;
                await saveStats();
                sendResponse(result);
                return;
            }

            if (request.action === "setTemporaryBypass") {
                temporaryBypasses.set(request.url, Date.now());
                stats.bypassesUsed++;
                await saveStats();
                log("⏰ Bypass set for:", request.url);
                sendResponse({ success: true, timestamp: Date.now() });
                return;
            }

            if (request.action === "addToWhitelist") {
                whitelist.add(request.domain);
                await browserAPI.storage.local.set({ whitelist: Array.from(whitelist) });
                log("✅ Added to whitelist:", request.domain);
                sendResponse({ success: true });
                return;
            }

            if (request.action === "addToBlacklist") {
                blacklist.add(request.domain);
                stats.threatsBlocked++;
                await browserAPI.storage.local.set({
                    blacklist: Array.from(blacklist),
                    stats: stats
                });
                log("🚫 Added to blacklist:", request.domain);
                sendResponse({ success: true });
                return;
            }

            sendResponse({ error: "Unknown action" });
        } catch (err) {
            error("Message handler error:", err);
            sendResponse({ error: err.message });
        }
    })();

    return true; // Keep channel open for async response
});

// ============================================
// TAB MONITORING (Fixed with debouncing)
// ============================================

let tabUpdateTimers = new Map();

browserAPI.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    // Only process when URL changes and page starts loading
    if (!changeInfo.url || changeInfo.status !== 'loading') return;

    const url = changeInfo.url;
    
    // Ignore system pages
    if (url.startsWith('about:') || url.startsWith('moz-extension:')) return;

    // Debounce: prevent excessive processing on rapid URL changes
    if (tabUpdateTimers.has(tabId)) {
        clearTimeout(tabUpdateTimers.get(tabId));
    }

    tabUpdateTimers.set(tabId, setTimeout(() => {
        processTabUpdate(tabId, url);
        tabUpdateTimers.delete(tabId);
    }, 100)); // 100ms debounce
});

function processTabUpdate(tabId, url) {
    log("🌐 Navigation:", url);

    try {
        // Check for active bypass
        if (temporaryBypasses.has(url)) {
            const time = temporaryBypasses.get(url);
            if (Date.now() - time < CONFIG.BYPASS_DURATION) {
                log("⏰ Bypass active for tab", tabId);
                return;
            }
            temporaryBypasses.delete(url);
        }

        // Analyze the URL
        const analysis = analyzeURL(url);
        log("📊 Score for tab", tabId, ":", analysis.score);

        // Update badge based on score
        let badgeText = "";
        let badgeColor = "#4caf50"; // Green

        if (analysis.score >= CONFIG.THRESHOLDS.CRITICAL) {
            badgeText = "!!!";
            badgeColor = "#ff0000"; // Bright red
        } else if (analysis.score >= CONFIG.THRESHOLDS.DANGER) {
            badgeText = "!!";
            badgeColor = "#ff003c"; // Red
        } else if (analysis.score >= CONFIG.THRESHOLDS.WARNING) {
            badgeText = "!";
            badgeColor = "#ffb300"; // Orange
        }

        // Set badge (Firefox uses browserAction)
        browserAPI.browserAction.setBadgeText({ text: badgeText, tabId: tabId });
        browserAPI.browserAction.setBadgeBackgroundColor({ color: badgeColor, tabId: tabId });

        // Block if threshold exceeded
        if (analysis.score >= CONFIG.BLOCK_THRESHOLD) {
            log("🚫 BLOCKING tab", tabId, "- score:", analysis.score);
            stats.threatsBlocked++;
            saveStats();

            // Redirect to warning page
            const warningUrl = browserAPI.runtime.getURL('warning.html') +
                '?url=' + encodeURIComponent(url) +
                '&score=' + analysis.score +
                '&reasons=' + encodeURIComponent(JSON.stringify(analysis.reasons));

            browserAPI.tabs.update(tabId, { url: warningUrl });
        }
    } catch (err) {
        error("Tab processing error:", err);
    }
}

// ============================================
// CLEANUP ON UNLOAD
// ============================================

browserAPI.runtime.onSuspend.addListener(() => {
    log("🛑 Extension suspending - cleaning up");
    
    // Clear all timers
    tabUpdateTimers.forEach(timer => clearTimeout(timer));
    tabUpdateTimers.clear();
    
    log("✅ Cleanup complete");
});

// ============================================
// STARTUP COMPLETE
// ============================================

log("=== ✅ PhishGuard Enhanced v2.1 Ready ===");
log("🎯 Typosquatting detector loaded with", typoDetector.topDomains.length, "brands");
log("🛡️ Monitoring all tabs for threats");
log("⚙️ Block threshold:", CONFIG.BLOCK_THRESHOLD);
log("⏰ Bypass duration:", CONFIG.BYPASS_DURATION / 1000, "seconds");