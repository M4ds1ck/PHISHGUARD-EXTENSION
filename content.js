// content.js - Universal Phishing Detection Engine
// Works on ALL websites - scans for threats regardless of domain

(function() {
    'use strict';
    
    // Prevent double injection
    if (window.phishGuardRunning) {
        console.log("PhishGuard: Already running");
        return;
    }
    
    window.phishGuardRunning = true;
    console.log("PhishGuard: Starting universal scan engine...");
    
    // Browser API compatibility
    const browserAPI = (typeof browser !== 'undefined') ? browser : chrome;
    
    // Check if utils loaded
    if (typeof PhishGuardUtils === 'undefined') {
        console.error("PhishGuard: Utils not loaded! Extension may not work properly.");
        // Define minimal utils inline as fallback
        window.PhishGuardUtils = {
            calculateEntropy: function(str) {
                if (!str) return 0;
                const freq = {};
                for (let char of str) freq[char] = (freq[char] || 0) + 1;
                return Object.values(freq).reduce((sum, f) => {
                    const p = f / str.length;
                    return sum - p * Math.log2(p);
                }, 0);
            },
            levenshteinDistance: function(a, b) {
                const matrix = Array(b.length + 1).fill(null).map(() => Array(a.length + 1).fill(0));
                for (let i = 0; i <= a.length; i++) matrix[0][i] = i;
                for (let j = 0; j <= b.length; j++) matrix[j][0] = j;
                for (let j = 1; j <= b.length; j++) {
                    for (let i = 1; i <= a.length; i++) {
                        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
                        matrix[j][i] = Math.min(
                            matrix[j][i - 1] + 1,
                            matrix[j - 1][i] + 1,
                            matrix[j - 1][i - 1] + cost
                        );
                    }
                }
                return matrix[b.length][a.length];
            },
            isIPAddress: function(host) {
                const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
                const ipv6 = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
                if (ipv4.test(host)) {
                    const parts = host.split('.').map(Number);
                    return { isIP: parts.every(n => n >= 0 && n <= 255), type: 'ipv4' };
                }
                if (ipv6.test(host)) return { isIP: true, type: 'ipv6' };
                return { isIP: false, type: null };
            },
            checkTyposquatting: function(domain, brands) {
                const results = [];
                const base = domain.split('.')[0].toLowerCase();
                for (const brand of brands) {
                    const dist = this.levenshteinDistance(base, brand.toLowerCase());
                    if (dist > 0 && dist <= 2) {
                        results.push({ target: brand, distance: dist });
                    }
                }
                return results.sort((a, b) => a.distance - b.distance);
            }
        };
    }
    
    // ============================================
    // CONFIGURATION - Universal Detection Rules
    // ============================================
    
    const CONFIG = {
        SUSPICIOUS_TLDS: [
            'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'click',
            'link', 'racing', 'loan', 'download', 'stream', 'party', 'review'
        ],
        
        // These are used ONLY to detect FAKE sites impersonating them
        // Example: "paypa1.com" would be flagged, but "paypal.com" is fine
        TRUSTED_BRANDS: [
            'google', 'paypal', 'apple', 'microsoft', 'facebook', 'amazon',
            'netflix', 'instagram', 'twitter', 'linkedin', 'github', 'gitlab'
        ],
        
        SUSPICIOUS_KEYWORDS: [
            'verify', 'account', 'secure', 'update', 'confirm', 'login',
            'banking', 'suspended', 'locked', 'urgent', 'expire'
        ]
    };
    
    // ============================================
    // HTTP WARNING BANNER
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
                animation: slideDown 0.3s ease-out;
            ">
                ⚠️ WARNING: This site uses insecure HTTP. Your data may be visible to others.
                <button onclick="this.parentElement.parentElement.remove()" style="
                    background: rgba(255,255,255,0.2); border: 1px solid white;
                    color: white; padding: 4px 12px; border-radius: 4px;
                    cursor: pointer; margin-left: 15px; font-weight: 600;
                ">Dismiss</button>
            </div>
            <style>
                @keyframes slideDown {
                    from { transform: translateY(-100%); opacity: 0; }
                    to { transform: translateY(0); opacity: 1; }
                }
            </style>
        `;
        document.body.appendChild(banner);
        
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
                <p style="margin: 10px 0; color: #ffaaaa;">
                    ⚠️ DO NOT enter passwords! Your data can be intercepted.
                </p>
                <button onclick="this.parentElement.parentElement.remove()" style="
                    background: #ff003c; border: none; color: white;
                    padding: 12px 30px; border-radius: 6px; cursor: pointer;
                    font-weight: 700; text-transform: uppercase;
                ">I Understand</button>
            </div>
            <div onclick="this.parentElement.remove()" style="
                position: fixed; top: 0; left: 0; right: 0; bottom: 0;
                background: rgba(0,0,0,0.8); z-index: 2147483646;
            "></div>
        `;
        document.body.appendChild(alert);
    }
    
    // ============================================
    // MAIN SCAN ENGINE - Works on ANY website
    // ============================================
    
    async function scanWebsite() {
        console.log("PhishGuard: Scanning", window.location.href);
        
        let score = 0;
        const reasons = [];
        
        const url = window.location.href;
        const hostname = window.location.hostname;
        const protocol = window.location.protocol;
        const parts = hostname.split('.');
        const tld = parts[parts.length - 1].toLowerCase();
        
        // ===== 1. HTTP CHECK =====
        if (protocol === 'http:') {
            showHTTPWarning();
            score += 15;
            reasons.push({
                reason: "Unencrypted HTTP Connection",
                weight: 15,
                detail: "Site doesn't use HTTPS encryption"
            });
            
            if (document.querySelector('input[type="password"]')) {
                showCriticalAlert();
                score += 50;
                reasons.push({
                    reason: "🚨 CRITICAL: Login Form on HTTP",
                    weight: 50,
                    detail: "Password fields on unencrypted connection"
                });
            }
        }
        
        // ===== 2. IP ADDRESS =====
        const ipCheck = PhishGuardUtils.isIPAddress(hostname);
        if (ipCheck.isIP) {
            score += 40;
            reasons.push({
                reason: "Direct IP Address Access",
                weight: 40,
                detail: `Using IP (${hostname}) instead of domain name`
            });
        }
        
        // ===== 3. SUSPICIOUS TLD =====
        if (CONFIG.SUSPICIOUS_TLDS.includes(tld)) {
            score += 20;
            reasons.push({
                reason: "High-Risk Domain Extension",
                weight: 20,
                detail: `.${tld} domains are often used in phishing`
            });
        }
        
        // ===== 4. DOMAIN ENTROPY (Randomness) =====
        const entropy = PhishGuardUtils.calculateEntropy(hostname);
        if (entropy > 4.5) {
            score += 25;
            reasons.push({
                reason: "Random-Looking Domain",
                weight: 25,
                detail: `Domain appears randomly generated (entropy: ${entropy.toFixed(2)})`
            });
        }
        
        // ===== 5. TOO MANY SUBDOMAINS =====
        if (parts.length > 4) {
            score += 15;
            reasons.push({
                reason: "Excessive Subdomains",
                weight: 15,
                detail: `${parts.length} subdomain levels detected`
            });
        }
        
        // ===== 6. TYPOSQUATTING (Fake brands) =====
        // This checks if site LOOKS LIKE a trusted brand but isn't
        const typos = PhishGuardUtils.checkTyposquatting(hostname, CONFIG.TRUSTED_BRANDS);
        if (typos.length > 0) {
            const match = typos[0];
            score += 45;
            reasons.push({
                reason: "⚠️ Possible Brand Impersonation",
                weight: 45,
                detail: `Domain resembles "${match.target}" (likely fake)`
            });
        }
        
        // ===== 7. BRAND NAME MISUSE =====
        for (const brand of CONFIG.TRUSTED_BRANDS) {
            const lower = hostname.toLowerCase();
            const hasBrand = lower.includes(brand);
            const isReal = lower === `${brand}.com` || lower === `www.${brand}.com` || lower.endsWith(`.${brand}.com`);
            
            if (hasBrand && !isReal) {
                score += 35;
                reasons.push({
                    reason: "Brand Name Misuse",
                    weight: 35,
                    detail: `Contains "${brand}" but not official domain`
                });
                break;
            }
        }
        
        // ===== 8. SUSPICIOUS KEYWORDS =====
        const urlLower = url.toLowerCase();
        const found = CONFIG.SUSPICIOUS_KEYWORDS.filter(kw => urlLower.includes(kw));
        if (found.length >= 2) {
            score += 20;
            reasons.push({
                reason: "Suspicious Keywords in URL",
                weight: 20,
                detail: `Found: ${found.join(', ')}`
            });
        }
        
        // ===== 9. LONG DOMAIN =====
        if (hostname.length > 40) {
            score += 15;
            reasons.push({
                reason: "Unusually Long Domain",
                weight: 15,
                detail: `${hostname.length} characters`
            });
        }
        
        // ===== 10. EXCESSIVE DASHES =====
        const dashes = (hostname.match(/-/g) || []).length;
        if (dashes > 2) {
            score += 10;
            reasons.push({
                reason: "Excessive Dashes in Domain",
                weight: 10,
                detail: `${dashes} dashes detected`
            });
        }
        
        // ===== 11. EXTERNAL FORMS =====
        const forms = document.querySelectorAll('form[action]');
        let externalForms = 0;
        forms.forEach(form => {
            const action = form.getAttribute('action');
            if (action && action.startsWith('http')) {
                try {
                    const actionHost = new URL(action).hostname;
                    if (actionHost !== hostname) externalForms++;
                } catch (e) {}
            }
        });
        
        if (externalForms > 0) {
            score += 30;
            reasons.push({
                reason: "Forms Submit to External Domain",
                weight: 30,
                detail: `${externalForms} forms send data elsewhere`
            });
        }
        
        // Cap score at 100
        score = Math.min(score, 100);
        
        // Create report
        const report = {
            score: score,
            reasons: reasons,
            url: url,
            hostname: hostname,
            protocol: protocol,
            timestamp: Date.now()
        };
        
        console.log("PhishGuard: Scan complete -", score, "points");
        
        // Send to background
        try {
            browserAPI.runtime.sendMessage({
                action: "reportRisk",
                data: report
            }, () => {
                if (browserAPI.runtime.lastError) {
                    console.warn("PhishGuard: Could not send report");
                }
            });
        } catch (e) {
            console.error("PhishGuard: Error sending report:", e);
        }
        
        return report;
    }
    
    // ============================================
    // MESSAGE LISTENER
    // ============================================
    
    browserAPI.runtime.onMessage.addListener((request, sender, sendResponse) => {
        console.log("PhishGuard: Message received:", request.action);
        
        if (request.action === "ping") {
            sendResponse({ status: "alive" });
            return true;
        }
        
        if (request.action === "manualScan") {
            scanWebsite().then(report => {
                sendResponse({ status: "complete", report: report });
            }).catch(error => {
                sendResponse({ status: "error", error: error.message });
            });
            return true;
        }
    });
    
    // ============================================
    // AUTO-SCAN ON PAGE LOAD
    // ============================================
    
    function init() {
        console.log("PhishGuard: Initializing scan...");
        setTimeout(scanWebsite, 1000);
    }
    
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
    
    console.log("PhishGuard: Ready for universal scanning");
    
})();