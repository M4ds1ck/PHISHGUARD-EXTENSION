// content.js - FIXED VERSION - Secure & Optimized
(function() {
    'use strict';

    if (window.phishGuardRunning) {
        console.log("PhishGuard: Already running");
        return;
    }

    window.phishGuardRunning = true;
    console.log("PhishGuard: Starting universal scan engine...");

    const browserAPI = browser;

    // Verify utils loaded
    if (typeof PhishGuardUtils === 'undefined') {
        console.error("PhishGuard: Utils not loaded!");
        window.PhishGuardUtils = {
            calculateEntropy: function(str) {
                if (!str) return 0;
                const freq = {};
                for (let char of str) freq[char] = (freq[char] || 0) + 1;
                return Object.values(freq).reduce((sum, f) => {
                    const p = f / str.length;
                    return sum - (p > 0 ? p * Math.log2(p) : 0);
                }, 0);
            },
            levenshteinDistance: function(a, b) {
                if (a === b) return 0;
                if (a.length === 0) return b.length;
                if (b.length === 0) return a.length;
                
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
                if (ipv4.test(host)) {
                    const parts = host.split('.').map(Number);
                    return { isIP: parts.every(n => n >= 0 && n <= 255), type: 'ipv4' };
                }
                const ipv6 = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
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
    // CONFIGURATION
    // ============================================

    const CONFIG = {
        // API KEYS - Store in browser.storage for security
        PHISHTANK_API_KEY: null,
        GOOGLE_SAFE_BROWSING_KEY: null,

        // Legitimate domains (for quick exit)
        LEGITIMATE_DOMAINS: [
            'google.com', 'youtube.com', 'gmail.com', 'microsoft.com', 'office.com',
            'apple.com', 'icloud.com', 'amazon.com', 'facebook.com', 'meta.com',
            'instagram.com', 'twitter.com', 'x.com', 'linkedin.com', 'reddit.com',
            'github.com', 'gitlab.com', 'stackoverflow.com', 'netflix.com', 'spotify.com',
            'paypal.com', 'stripe.com', 'ebay.com', 'walmart.com', 'target.com'
        ],

        SUSPICIOUS_TLDS: [
            'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'click',
            'link', 'racing', 'loan', 'download', 'stream', 'party', 'review'
        ],

        BRAND_NAMES: [
            'google', 'paypal', 'apple', 'microsoft', 'facebook', 'amazon',
            'netflix', 'instagram', 'twitter', 'linkedin', 'github'
        ],

        SUSPICIOUS_KEYWORDS: [
            'verify', 'account', 'secure', 'update', 'confirm', 'login',
            'banking', 'suspended', 'locked', 'urgent', 'expire'
        ]
    };

    // ============================================
    // LEGITIMATE DOMAIN CHECK (Fixed)
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
            ">
                ⚠️ WARNING: This site uses insecure HTTP. Your data may be visible to others.
                <button onclick="this.parentElement.parentElement.remove()" style="
                    background: rgba(255,255,255,0.2); border: 1px solid white;
                    color: white; padding: 4px 12px; border-radius: 4px;
                    cursor: pointer; margin-left: 15px; font-weight: 600;
                ">Dismiss</button>
            </div>
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
    // API INTEGRATION (Fixed with parallel calls)
    // ============================================

    async function checkPhishTank(url) {
        if (!CONFIG.PHISHTANK_API_KEY) return { isListed: false };

        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 5000);

            const response = await fetch('https://checkurl.phishtank.com/checkurl/', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `url=${encodeURIComponent(url)}&format=json&app_key=${CONFIG.PHISHTANK_API_KEY}`,
                signal: controller.signal
            });

            clearTimeout(timeout);

            if (response.ok) {
                const data = await response.json();
                return {
                    isListed: data.results?.in_database === true,
                    verified: data.results?.verified === true
                };
            }
        } catch (error) {
            console.warn("PhishGuard: PhishTank check failed:", error.message);
        }

        return { isListed: false };
    }

    async function checkGoogleSafeBrowsing(url) {
        if (!CONFIG.GOOGLE_SAFE_BROWSING_KEY) return { isThreat: false };

        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 5000);

            const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${CONFIG.GOOGLE_SAFE_BROWSING_KEY}`;

            const response = await fetch(apiUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    client: {
                        clientId: "phishguard",
                        clientVersion: "2.1.0"
                    },
                    threatInfo: {
                        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                        platformTypes: ["ANY_PLATFORM"],
                        threatEntryTypes: ["URL"],
                        threatEntries: [{ url: url }]
                    }
                }),
                signal: controller.signal
            });

            clearTimeout(timeout);

            if (response.ok) {
                const data = await response.json();
                return {
                    isThreat: data.matches && data.matches.length > 0,
                    threats: data.matches || []
                };
            }
        } catch (error) {
            console.warn("PhishGuard: Google Safe Browsing check failed:", error.message);
        }

        return { isThreat: false };
    }

    // ============================================
    // MAIN SCAN ENGINE (Fixed with proper logic)
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

        // ===== LEGITIMATE CHECK - But don't skip all checks =====
        const isLegit = isLegitimateWebsite(hostname);
        
        if (isLegit) {
            console.log("PhishGuard: Recognized legitimate site");
            
            // Still warn about HTTP on legitimate sites
            if (protocol === 'http:') {
                showHTTPWarning();
                score = 15;
                reasons.push({
                    reason: "Legitimate site using insecure HTTP",
                    weight: 15,
                    detail: "This is a real site but not using HTTPS encryption"
                });

                // Check for password fields
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

            // Send report and return
            const report = {
                score: score,
                reasons: reasons,
                url: url,
                hostname: hostname,
                protocol: protocol,
                legitimate: true,
                timestamp: Date.now()
            };

            sendReport(report);
            return report;
        }

        // ===== FULL SCAN FOR NON-LEGITIMATE SITES =====

        // HTTP check
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

        // IP Address
        const ipCheck = PhishGuardUtils.isIPAddress(hostname);
        if (ipCheck.isIP) {
            score += 40;
            reasons.push({
                reason: "Direct IP Address Access",
                weight: 40,
                detail: `Using ${ipCheck.type.toUpperCase()} address instead of domain name`
            });
        }

        // Suspicious TLD
        if (CONFIG.SUSPICIOUS_TLDS.includes(tld)) {
            score += 20;
            reasons.push({
                reason: "High-Risk Domain Extension",
                weight: 20,
                detail: `.${tld} domains are often used in phishing`
            });
        }

        // Domain Entropy
        const entropy = PhishGuardUtils.calculateEntropy(hostname);
        if (entropy > 4.5) {
            score += 25;
            reasons.push({
                reason: "Random-Looking Domain",
                weight: 25,
                detail: `Domain appears randomly generated (entropy: ${entropy.toFixed(2)})`
            });
        }

        // Too Many Subdomains
        if (parts.length > 4) {
            score += 15;
            reasons.push({
                reason: "Excessive Subdomains",
                weight: 15,
                detail: `${parts.length} subdomain levels detected`
            });
        }

        // Typosquatting
        const baseDomain = extractBaseDomain(hostname);
        const typos = PhishGuardUtils.checkTyposquatting(baseDomain, CONFIG.BRAND_NAMES);
        if (typos.length > 0) {
            const match = typos[0];
            score += 50;
            reasons.push({
                reason: "⚠️ Possible Brand Impersonation",
                weight: 50,
                detail: `Domain resembles "${match.target}" (${match.distance} character difference)`
            });
        }

        // Brand Name Misuse
        for (const brand of CONFIG.BRAND_NAMES) {
            const lower = hostname.toLowerCase();
            if (lower.includes(brand) && !lower.endsWith(`${brand}.com`)) {
                score += 35;
                reasons.push({
                    reason: "Brand Name Misuse",
                    weight: 35,
                    detail: `Contains "${brand}" but not the official domain`
                });
                break;
            }
        }

        // Suspicious Keywords
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

        // Long Domain
        if (hostname.length > 40) {
            score += 15;
            reasons.push({
                reason: "Unusually Long Domain",
                weight: 15,
                detail: `${hostname.length} characters`
            });
        }

        // Excessive Dashes
        const dashes = (hostname.match(/-/g) || []).length;
        if (dashes > 2) {
            score += 10;
            reasons.push({
                reason: "Excessive Dashes in Domain",
                weight: 10,
                detail: `${dashes} dashes detected`
            });
        }

        // External Forms
        const forms = document.querySelectorAll('form[action]');
        let externalForms = 0;
        forms.forEach(form => {
            try {
                const action = form.getAttribute('action');
                if (action && action.startsWith('http')) {
                    const actionHost = new URL(action).hostname;
                    if (actionHost !== hostname) externalForms++;
                }
            } catch (e) {}
        });

        if (externalForms > 0) {
            score += 30;
            reasons.push({
                reason: "Forms Submit to External Domain",
                weight: 30,
                detail: `${externalForms} forms send data elsewhere`
            });
        }

        // API Checks (Parallel for speed)
        try {
            console.log("PhishGuard: Checking threat databases...");

            const [phishTankResult, googleResult] = await Promise.all([
                checkPhishTank(url),
                checkGoogleSafeBrowsing(url)
            ]);

            if (phishTankResult.isListed) {
                score += 80;
                reasons.push({
                    reason: "🚨 CONFIRMED: Listed in PhishTank Database",
                    weight: 80,
                    detail: `This URL is confirmed as phishing${phishTankResult.verified ? ' (verified)' : ''}`
                });
            }

            if (googleResult.isThreat) {
                score += 80;
                const threatTypes = googleResult.threats.map(t => t.threatType).join(', ');
                reasons.push({
                    reason: "🚨 CONFIRMED: Flagged by Google Safe Browsing",
                    weight: 80,
                    detail: `Threat types: ${threatTypes}`
                });
            }
        } catch (error) {
            console.warn("PhishGuard: API checks failed:", error);
        }

        // Cap score
        score = Math.min(score, 100);

        const report = {
            score: score,
            reasons: reasons,
            url: url,
            hostname: hostname,
            protocol: protocol,
            timestamp: Date.now()
        };

        console.log("PhishGuard: Scan complete - Score:", score);
        sendReport(report);
        return report;
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
                console.warn("PhishGuard: Could not send report:", error);
            });
        } catch (e) {
            console.error("PhishGuard: Error sending report:", e);
        }
    }

    // ============================================
    // MESSAGE LISTENER
    // ============================================

    browserAPI.runtime.onMessage.addListener((request, sender, sendResponse) => {
        console.log("PhishGuard: Message received:", request.action);

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