// utils.js - FIXED & OPTIMIZED VERSION

const PhishGuardUtils = {

    // ============================================
    // STRING ANALYSIS
    // ============================================

    /**
     * Calculate Shannon entropy (fixed divide-by-zero bug)
     */
    calculateEntropy: function(str) {
        if (!str || str.length === 0) return 0;

        const len = str.length;
        const frequencies = {};

        for (let i = 0; i < len; i++) {
            const char = str[i];
            frequencies[char] = (frequencies[char] || 0) + 1;
        }

        return Object.values(frequencies).reduce((sum, freq) => {
            const probability = freq / len;
            // Fix: Check for zero probability to avoid -Infinity
            if (probability > 0) {
                return sum - probability * Math.log2(probability);
            }
            return sum;
        }, 0);
    },

    /**
     * Optimized Levenshtein distance with early exit
     */
    levenshteinDistance: function(str1, str2) {
        // Early exits
        if (str1 === str2) return 0;
        if (str1.length === 0) return str2.length;
        if (str2.length === 0) return str1.length;

        const len1 = str1.length;
        const len2 = str2.length;

        // Optimization: swap to ensure str1 is shorter
        if (len1 > len2) {
            return this.levenshteinDistance(str2, str1);
        }

        // Use single array instead of matrix (space optimization)
        let prevRow = Array(len1 + 1).fill(0).map((_, i) => i);
        
        for (let j = 1; j <= len2; j++) {
            let currRow = [j];
            
            for (let i = 1; i <= len1; i++) {
                const cost = str1[i - 1] === str2[j - 1] ? 0 : 1;
                currRow[i] = Math.min(
                    prevRow[i] + 1,      // Deletion
                    currRow[i - 1] + 1,  // Insertion
                    prevRow[i - 1] + cost // Substitution
                );
            }
            
            prevRow = currRow;
        }

        return prevRow[len1];
    },

    /**
     * Check for homograph characters (IDN attacks)
     */
    hasHomographs: function(str) {
        // Comprehensive homograph character set
        const homographs = new Set([
            // Cyrillic
            '\u0430', '\u0435', '\u043E', '\u0440', '\u0441',
            '\u0445', '\u0443', '\u0456', '\u0458', '\u0455',
            // Greek
            '\u03BF', '\u03C1', '\u03B1', '\u03B5', '\u03B9',
            '\u03C4', '\u03C5', '\u03C7'
        ]);

        for (const char of str) {
            if (homographs.has(char)) return true;
        }

        return false;
    },

    // ============================================
    // URL ANALYSIS
    // ============================================

    /**
     * Extract base domain from hostname
     */
    extractDomain: function(hostname) {
        const parts = hostname.split('.');
        if (parts.length >= 2) {
            return parts.slice(-2).join('.');
        }
        return hostname;
    },

    /**
     * Validate IP address (fixed validation)
     */
    isIPAddress: function(hostname) {
        // IPv4 pattern with proper validation
        const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (ipv4Pattern.test(hostname)) {
            const octets = hostname.split('.').map(Number);
            const valid = octets.every(octet => octet >= 0 && octet <= 255);
            return { isIP: valid, type: 'ipv4' };
        }

        // IPv6 pattern (simplified but more accurate)
        const ipv6Pattern = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
        if (ipv6Pattern.test(hostname)) {
            return { isIP: true, type: 'ipv6' };
        }

        return { isIP: false, type: null };
    },

    /**
     * Check for typosquatting (optimized)
     */
    checkTyposquatting: function(domain, targetList, threshold = 2) {
        const results = [];
        const domainBase = domain.split('.')[0].toLowerCase();

        // Pre-filter by length (optimization)
        const maxLength = domainBase.length + threshold;
        const minLength = Math.max(1, domainBase.length - threshold);

        for (const target of targetList) {
            const targetLower = target.toLowerCase();
            
            // Skip if length difference too large
            if (targetLower.length > maxLength || targetLower.length < minLength) {
                continue;
            }

            const distance = this.levenshteinDistance(domainBase, targetLower);

            if (distance > 0 && distance <= threshold) {
                results.push({
                    target: target,
                    distance: distance,
                    similarity: 1 - (distance / Math.max(domainBase.length, targetLower.length))
                });
            }
        }

        return results.sort((a, b) => a.distance - b.distance);
    },

    /**
     * Count pattern occurrences
     */
    countPattern: function(str, pattern) {
        if (typeof pattern === 'string') {
            return (str.match(new RegExp(pattern, 'g')) || []).length;
        }
        return (str.match(pattern) || []).length;
    },

    // ============================================
    // DOMAIN VALIDATION
    // ============================================

    /**
     * Validate domain structure
     */
    validateDomainStructure: function(hostname) {
        const parts = hostname.split('.');
        const tld = parts[parts.length - 1];

        return {
            subdomainCount: Math.max(0, parts.length - 2),
            hasExcessiveSubdomains: parts.length > 4,
            tld: tld,
            length: hostname.length,
            isLong: hostname.length > 40,
            dashCount: this.countPattern(hostname, /-/g),
            underscoreCount: this.countPattern(hostname, /_/g),
            digitCount: this.countPattern(hostname, /\d/g),
            hasExcessiveSpecialChars: this.countPattern(hostname, /-/g) > 2 ||
                                       this.countPattern(hostname, /_/g) > 1
        };
    },

    // ============================================
    // HEURISTIC HELPERS
    // ============================================

    /**
     * Find suspicious keywords
     */
    findSuspiciousKeywords: function(url, keywords) {
        const urlLower = url.toLowerCase();
        return keywords.filter(keyword => urlLower.includes(keyword.toLowerCase()));
    },

    /**
     * Detect brand impersonation
     */
    detectBrandImpersonation: function(hostname, brand) {
        const hostLower = hostname.toLowerCase();
        const brandLower = brand.toLowerCase();

        // Legitimate patterns
        const legitPatterns = [
            `${brandLower}.com`,
            `www.${brandLower}.com`,
            `${brandLower}.org`,
            `${brandLower}.net`
        ];

        const isLegit = legitPatterns.some(pattern => {
            return hostLower === pattern || hostLower.endsWith(`.${pattern}`);
        });

        if (isLegit) {
            return { isImpersonation: false, method: null };
        }

        // Check suspicious patterns
        if (hostLower.includes(brandLower)) {
            // Subdomain: paypal.evil.com
            if (hostLower.startsWith(brandLower + '.')) {
                return { isImpersonation: true, method: 'subdomain' };
            }

            // With dash: paypal-login.com
            if (hostLower.includes(brandLower + '-') || hostLower.includes('-' + brandLower)) {
                return { isImpersonation: true, method: 'dash-prefix' };
            }

            // Embedded: login.paypal-secure.com
            return { isImpersonation: true, method: 'embedded' };
        }

        return { isImpersonation: false, method: null };
    },

    // ============================================
    // URL SHORTENER DETECTION
    // ============================================

    /**
     * Check if URL uses shortening service
     */
    isShortener: function(hostname) {
        const shorteners = new Set([
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
            'is.gd', 'buff.ly', 'adf.ly', 'bl.ink', 'lnkd.in',
            'shorte.st', 'mcaf.ee', 'su.pr', 'bc.vc', 'youtu.be',
            'j.mp', 'tr.im', 'cli.gs', 'tiny.cc', 'url.ie'
        ]);

        const lower = hostname.toLowerCase();
        for (const shortener of shorteners) {
            if (lower.includes(shortener)) return true;
        }
        return false;
    },

    // ============================================
    // SIMILARITY FUNCTIONS
    // ============================================

    /**
     * Jaro-Winkler similarity (alternative metric)
     */
    jaroWinklerSimilarity: function(s1, s2) {
        if (s1 === s2) return 1.0;

        const len1 = s1.length;
        const len2 = s2.length;

        if (len1 === 0 || len2 === 0) return 0.0;

        const matchDistance = Math.floor(Math.max(len1, len2) / 2) - 1;
        const s1Matches = new Array(len1).fill(false);
        const s2Matches = new Array(len2).fill(false);

        let matches = 0;
        let transpositions = 0;

        // Find matches
        for (let i = 0; i < len1; i++) {
            const start = Math.max(0, i - matchDistance);
            const end = Math.min(i + matchDistance + 1, len2);

            for (let j = start; j < end; j++) {
                if (s2Matches[j] || s1[i] !== s2[j]) continue;
                s1Matches[i] = true;
                s2Matches[j] = true;
                matches++;
                break;
            }
        }

        if (matches === 0) return 0.0;

        // Find transpositions
        let k = 0;
        for (let i = 0; i < len1; i++) {
            if (!s1Matches[i]) continue;
            while (!s2Matches[k]) k++;
            if (s1[i] !== s2[k]) transpositions++;
            k++;
        }

        const jaro = (matches / len1 + matches / len2 +
                     (matches - transpositions / 2) / matches) / 3;

        return jaro;
    },

    // ============================================
    // DATA VALIDATION & UTILITIES
    // ============================================

    /**
     * Sanitize string for safe display (XSS prevention)
     */
    sanitize: function(str) {
        if (typeof str !== 'string') return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    },

    /**
     * Format timestamp
     */
    formatTimestamp: function(timestamp) {
        try {
            const date = new Date(timestamp);
            return date.toLocaleString();
        } catch (e) {
            return 'Invalid date';
        }
    },

    /**
     * Deep clone object safely
     */
    deepClone: function(obj) {
        try {
            return JSON.parse(JSON.stringify(obj));
        } catch (e) {
            console.error('Deep clone failed:', e);
            return null;
        }
    },

    /**
     * Debounce function (utility for performance)
     */
    debounce: function(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },

    /**
     * Throttle function (utility for performance)
     */
    throttle: function(func, limit) {
        let inThrottle;
        return function executedFunction(...args) {
            if (!inThrottle) {
                func.apply(this, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    }
};

// Make utilities globally available
if (typeof window !== 'undefined') {
    window.PhishGuardUtils = PhishGuardUtils;
}

// Export for Node.js (if needed)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = PhishGuardUtils;
}

console.log("PhishGuard Utils: Loaded & Optimized");