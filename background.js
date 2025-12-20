// background.js - Enhanced Background Service Worker
console.log("PhishGuard Background Service: Initializing...");

// Risk cache storage
const riskCache = new Map();
const CACHE_EXPIRY = 5 * 60 * 1000; // 5 minutes

// Whitelist management
let whitelist = new Set();
let blacklist = new Set();

// Stats tracking
let stats = {
    threatsBlocked: 0,
    sitesScanned: 0,
    lastUpdate: Date.now()
};

// ============================================
// INITIALIZATION
// ============================================

chrome.runtime.onInstalled.addListener(async (details) => {
    console.log("PhishGuard: Extension installed/updated");
    
    // Load saved data
    await loadStoredData();
    
    // Bootstrap all existing tabs
    if (details.reason === "install" || details.reason === "update") {
        await bootstrapAllTabs();
    }
    
    // Set up periodic cleanup
    chrome.alarms.create("cleanupCache", { periodInMinutes: 10 });
});

// Load whitelist, blacklist, and stats from storage
async function loadStoredData() {
    try {
        const data = await chrome.storage.local.get(['whitelist', 'blacklist', 'stats']);
        
        if (data.whitelist) {
            whitelist = new Set(data.whitelist);
            console.log(`Loaded ${whitelist.size} whitelisted domains`);
        }
        
        if (data.blacklist) {
            blacklist = new Set(data.blacklist);
            console.log(`Loaded ${blacklist.size} blacklisted domains`);
        }
        
        if (data.stats) {
            stats = { ...stats, ...data.stats };
            console.log("Stats loaded:", stats);
        }
    } catch (error) {
        console.error("Error loading stored data:", error);
    }
}

// Save data to storage
async function saveToStorage(key, value) {
    try {
        await chrome.storage.local.set({ [key]: value });
    } catch (error) {
        console.error(`Error saving ${key}:`, error);
    }
}

// Bootstrap content scripts into all tabs
async function bootstrapAllTabs() {
    console.log("Bootstrapping content scripts into existing tabs...");
    
    try {
        const tabs = await chrome.tabs.query({});
        let injected = 0;
        let skipped = 0;

        for (const tab of tabs) {
            // Skip restricted URLs
            if (!tab.url || 
                tab.url.startsWith("chrome:") || 
                tab.url.startsWith("about:") || 
                tab.url.startsWith("moz-extension:") ||
                tab.url.startsWith("chrome-extension:") ||
                tab.url.startsWith("edge:") ||
                tab.url.startsWith("opera:")) {
                skipped++;
                continue;
            }

            try {
                // Inject utils.js first, then content.js
                await chrome.scripting.executeScript({
                    target: { tabId: tab.id },
                    files: ["utils.js"]
                });
                
                await chrome.scripting.executeScript({
                    target: { tabId: tab.id },
                    files: ["content.js"]
                });
                
                injected++;
                console.log(`✓ Bootstrapped tab ${tab.id}: ${tab.url}`);
            } catch (err) {
                console.warn(`✗ Failed to bootstrap tab ${tab.id}:`, err.message);
                skipped++;
            }
        }
        
        console.log(`Bootstrap complete: ${injected} injected, ${skipped} skipped`);
    } catch (error) {
        console.error("Bootstrap error:", error);
    }
}

// ============================================
// CACHE MANAGEMENT
// ============================================

function setCacheEntry(tabId, data) {
    riskCache.set(tabId, {
        data: data,
        timestamp: Date.now()
    });
    
    // Update stats
    stats.sitesScanned++;
    if (data.score >= 50) {
        stats.threatsBlocked++;
    }
    stats.lastUpdate = Date.now();
    saveToStorage('stats', stats);
}

function getCacheEntry(tabId) {
    const entry = riskCache.get(tabId);
    
    if (!entry) return null;
    
    // Check if cache is expired
    const age = Date.now() - entry.timestamp;
    if (age > CACHE_EXPIRY) {
        riskCache.delete(tabId);
        return null;
    }
    
    return entry.data;
}

function clearCacheEntry(tabId) {
    riskCache.delete(tabId);
    updateBadge(tabId, 0);
}

// Periodic cleanup of expired cache entries
chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === "cleanupCache") {
        const now = Date.now();
        let cleaned = 0;
        
        for (const [tabId, entry] of riskCache.entries()) {
            if (now - entry.timestamp > CACHE_EXPIRY) {
                riskCache.delete(tabId);
                cleaned++;
            }
        }
        
        if (cleaned > 0) {
            console.log(`Cache cleanup: removed ${cleaned} expired entries`);
        }
    }
});

// ============================================
// WHITELIST/BLACKLIST MANAGEMENT
// ============================================

function addToWhitelist(domain) {
    whitelist.add(domain);
    saveToStorage('whitelist', Array.from(whitelist));
    console.log(`Added to whitelist: ${domain}`);
}

function removeFromWhitelist(domain) {
    whitelist.delete(domain);
    saveToStorage('whitelist', Array.from(whitelist));
    console.log(`Removed from whitelist: ${domain}`);
}

function addToBlacklist(domain) {
    blacklist.add(domain);
    saveToStorage('blacklist', Array.from(blacklist));
    console.log(`Added to blacklist: ${domain}`);
}

function isWhitelisted(url) {
    try {
        const hostname = new URL(url).hostname;
        return whitelist.has(hostname);
    } catch {
        return false;
    }
}

function isBlacklisted(url) {
    try {
        const hostname = new URL(url).hostname;
        return blacklist.has(hostname);
    } catch {
        return false;
    }
}

// ============================================
// BADGE MANAGEMENT
// ============================================

function updateBadge(tabId, score) {
    if (score >= 75) {
        chrome.action.setBadgeText({ text: "!!!", tabId: tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#ff0000", tabId: tabId });
    } else if (score >= 50) {
        chrome.action.setBadgeText({ text: "!!", tabId: tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#ff003c", tabId: tabId });
    } else if (score >= 25) {
        chrome.action.setBadgeText({ text: "!", tabId: tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#ffb300", tabId: tabId });
    } else if (score > 0) {
        chrome.action.setBadgeText({ text: "?", tabId: tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#4caf50", tabId: tabId });
    } else {
        chrome.action.setBadgeText({ text: "", tabId: tabId });
    }
}

// ============================================
// MESSAGE HANDLING
// ============================================

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    const tabId = sender.tab ? sender.tab.id : request.tabId;
    
    // Store risk report from content script
    if (request.action === "reportRisk") {
        const data = request.data;
        
        // Check if domain is whitelisted or blacklisted
        if (isWhitelisted(data.url)) {
            data.score = 0;
            data.reasons = [{
                reason: "Whitelisted Domain",
                weight: 0,
                detail: "This domain is in your trusted list"
            }];
        } else if (isBlacklisted(data.url)) {
            data.score = 100;
            data.reasons = [{
                reason: "BLACKLISTED DOMAIN",
                weight: 100,
                detail: "This domain is in your blocked list"
            }];
        }
        
        setCacheEntry(tabId, data);
        updateBadge(tabId, data.score);
        
        console.log(`Risk report for tab ${tabId}: Score ${data.score}`);
        sendResponse({ status: "received" });
        return true;
    }
    
    // Serve cached risk data to popup
    if (request.action === "getCachedRisk") {
        const cached = getCacheEntry(request.tabId);
        sendResponse(cached);
        return true;
    }
    
    // Get stats
    if (request.action === "getStats") {
        sendResponse(stats);
        return true;
    }
    
    // Whitelist management
    if (request.action === "addToWhitelist") {
        addToWhitelist(request.domain);
        clearCacheEntry(request.tabId);
        sendResponse({ success: true });
        return true;
    }
    
    if (request.action === "removeFromWhitelist") {
        removeFromWhitelist(request.domain);
        sendResponse({ success: true });
        return true;
    }
    
    // Blacklist management
    if (request.action === "addToBlacklist") {
        addToBlacklist(request.domain);
        clearCacheEntry(request.tabId);
        sendResponse({ success: true });
        return true;
    }
    
    // Get whitelist/blacklist
    if (request.action === "getWhitelist") {
        sendResponse(Array.from(whitelist));
        return true;
    }
    
    if (request.action === "getBlacklist") {
        sendResponse(Array.from(blacklist));
        return true;
    }
    
    // Force reload tab (auto-fix mechanism)
    if (request.action === "forceFixTab") {
        chrome.tabs.reload(tabId, {}, () => {
            console.log(`Tab ${tabId} reloaded (auto-fix)`);
            sendResponse({ status: "reloading" });
        });
        return true;
    }
    
    // Clear cache for specific tab
    if (request.action === "clearCache") {
        clearCacheEntry(request.tabId);
        sendResponse({ status: "cleared" });
        return true;
    }
});

// ============================================
// TAB LIFECYCLE MANAGEMENT
// ============================================

// Clear cache when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
    riskCache.delete(tabId);
});

// Clear cache and badge when tab is updated (navigation)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === "loading" && changeInfo.url) {
        clearCacheEntry(tabId);
    }
});

console.log("PhishGuard Background Service: Ready");