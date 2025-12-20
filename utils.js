// utils.js - Shared Utility Functions
// This file is loaded before content.js and provides reusable functions

const PhishGuardUtils = {
    
    // ============================================
    // STRING ANALYSIS
    // ============================================
    
    /**
     * Calculate Shannon entropy of a string (measures randomness)
     * Higher entropy = more random = potentially suspicious
     * @param {string} str - String to analyze
     * @returns {number} Entropy value
     */
    calculateEntropy: function(str) {
        if (!str || str.length === 0) return 0;
        
        const len = str.length;
        const frequencies = {};
        
        // Count character frequencies
        for (let i = 0; i < len; i++) {
            const char = str[i];
            frequencies[char] = (frequencies[char] || 0) + 1;
        }
        
        // Calculate entropy
        return Object.values(frequencies).reduce((sum, freq) => {
            const probability = freq / len;
            return sum - probability * Math.log2(probability);
        }, 0);
    },
    
    /**
     * Calculate Levenshtein distance between two strings
     * Used for typosquatting detection
     * @param {string} str1 - First string
     * @param {string} str2 - Second string
     * @returns {number} Edit distance
     */
    levenshteinDistance: function(str1, str2) {
        const len1 = str1.length;
        const len2 = str2.length;
        
        // Create matrix
        const matrix = Array(len2 + 1)
            .fill(null)
            .map(() => Array(len1 + 1).fill(0));
        
        // Initialize first row and column
        for (let i = 0; i <= len1; i++) matrix[0][i] = i;
        for (let j = 0; j <= len2; j++) matrix[j][0] = j;
        
        // Fill matrix
        for (let j = 1; j <= len2; j++) {
            for (let i = 1; i <= len1; i++) {
                const cost = str1[i - 1] === str2[j - 1] ? 0 : 1;
                matrix[j][i] = Math.min(
                    matrix[j][i - 1] + 1,     // Insertion
                    matrix[j - 1][i] + 1,     // Deletion
                    matrix[j - 1][i - 1] + cost // Substitution
                );
            }
        }
        
        return matrix[len2][len1];
    },
    
    /**
     * Check for homograph characters (visually similar characters)
     * Common in IDN homograph attacks
     * @param {string} str - String to check
     * @returns {boolean} True if suspicious characters found
     */
    hasHomographs: function(str) {
        // Common homograph characters
        const homographs = [
            '\u0430', // Cyrillic 'a'
            '\u0435', // Cyrillic 'e'
            '\u043E', // Cyrillic 'o'
            '\u0440', // Cyrillic 'p'
            '\u0441', // Cyrillic 'c'
            '\u0445', // Cyrillic 'x'
            '\u0443', // Cyrillic 'y'
            '\u03BF', // Greek 'o'
            '\u03C1', // Greek 'p'
        ];
        
        for (const char of str) {
            if (homographs.includes(char)) return true;
        }
        
        return false;
    },
    
    // ============================================
    // URL ANALYSIS
    // ============================================
    
    /**
     * Extract base domain from hostname
     * @param {string} hostname - Full hostname
     * @returns {string} Base domain
     */
    extractDomain: function(hostname) {
        const parts = hostname.split('.');
        if (parts.length >= 2) {
            return parts.slice(-2).join('.');
        }
        return hostname;
    },
    
    /**
     * Check if URL uses IP address instead of domain
     * @param {string} hostname - Hostname to check
     * @returns {object} {isIP: boolean, type: 'ipv4'|'ipv6'|null}
     */
    isIPAddress: function(hostname) {
        // IPv4 pattern
        const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (ipv4Pattern.test(hostname)) {
            // Validate octets are 0-255
            const octets = hostname.split('.').map(Number);
            const valid = octets.every(octet => octet >= 0 && octet <= 255);
            return { isIP: valid, type: 'ipv4' };
        }
        
        // IPv6 pattern (simplified)
        const ipv6Pattern = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
        if (ipv6Pattern.test(hostname)) {
            return { isIP: true, type: 'ipv6' };
        }
        
        return { isIP: false, type: null };
    },
    
    /**
     * Check for typosquatting against known brands
     * @param {string} domain - Domain to check
     * @param {array} targetList - List of legitimate domains
     * @param {number} threshold - Maximum edit distance (default: 2)
     * @returns {array} Array of matches with {target, distance}
     */
    checkTyposquatting: function(domain, targetList, threshold = 2) {
        const results = [];
        const domainBase = domain.split('.')[0].toLowerCase();
        
        for (const target of targetList) {
            const targetLower = target.toLowerCase();
            const distance = this.levenshteinDistance(domainBase, targetLower);
            
            if (distance > 0 && distance <= threshold) {
                results.push({ 
                    target: target, 
                    distance: distance,
                    similarity: 1 - (distance / Math.max(domainBase.length, targetLower.length))
                });
            }
        }
        
        // Sort by distance (closest first)
        return results.sort((a, b) => a.distance - b.distance);
    },
    
    /**
     * Count occurrences of a pattern in string
     * @param {string} str - String to search
     * @param {RegExp|string} pattern - Pattern to count
     * @returns {number} Number of occurrences
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
     * Check if domain is likely legitimate based on structure
     * @param {string} hostname - Hostname to check
     * @returns {object} Validation results
     */
    validateDomainStructure: function(hostname) {
        const parts = hostname.split('.');
        const tld = parts[parts.length - 1];
        
        return {
            subdomainCount: parts.length - 2,
            hasExcessiveSubdomains: parts.length > 4,
            tld: tld,
            length: hostname.length,
            isLong: hostname.length > 40,
            dashCount: this.countPattern(hostname, '-'),
            underscoreCount: this.countPattern(hostname, '_'),
            digitCount: this.countPattern(hostname, /\d/g),
            hasExcessiveSpecialChars: this.countPattern(hostname, '-') > 2 || 
                                       this.countPattern(hostname, '_') > 1
        };
    },
    
    // ============================================
    // HEURISTIC HELPERS
    // ============================================
    
    /**
     * Check if URL contains suspicious keyword combinations
     * @param {string} url - Full URL to check
     * @param {array} keywords - Array of suspicious keywords
     * @returns {array} Found keywords
     */
    findSuspiciousKeywords: function(url, keywords) {
        const urlLower = url.toLowerCase();
        return keywords.filter(keyword => urlLower.includes(keyword.toLowerCase()));
    },
    
    /**
     * Detect brand impersonation attempts
     * @param {string} hostname - Hostname to check
     * @param {string} brand - Brand name to check against
     * @returns {object} {isImpersonation: boolean, method: string}
     */
    detectBrandImpersonation: function(hostname, brand) {
        const hostLower = hostname.toLowerCase();
        const brandLower = brand.toLowerCase();
        
        // Check if domain legitimately belongs to brand
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
        
        // Check if brand name appears in suspicious ways
        if (hostLower.includes(brandLower)) {
            // As subdomain: paypal.evil.com
            if (hostLower.startsWith(brandLower + '.')) {
                return { isImpersonation: true, method: 'subdomain' };
            }
            
            // With dash: paypal-login.com
            if (hostLower.includes(brandLower + '-') || hostLower.includes('-' + brandLower)) {
                return { isImpersonation: true, method: 'dash-prefix' };
            }
            
            // In subdomain: login.paypal-secure.com
            return { isImpersonation: true, method: 'embedded' };
        }
        
        return { isImpersonation: false, method: null };
    },
    
    // ============================================
    // URL SHORTENER DETECTION
    // ============================================
    
    /**
     * Check if URL uses a known shortening service
     * @param {string} hostname - Hostname to check
     * @returns {boolean} True if shortener detected
     */
    isShortener: function(hostname) {
        const shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
            'is.gd', 'buff.ly', 'adf.ly', 'bl.ink', 'lnkd.in',
            'shorte.st', 'mcaf.ee', 'su.pr', 'bc.vc', 'youtu.be',
            'j.mp', 'tr.im', 'cli.gs', 'tiny.cc', 'url.ie'
        ];
        
        return shorteners.some(shortener => hostname.includes(shortener));
    },
    
    // ============================================
    // SIMILARITY FUNCTIONS
    // ============================================
    
    /**
     * Calculate Jaro-Winkler similarity (alternative to Levenshtein)
     * @param {string} s1 - First string
     * @param {string} s2 - Second string
     * @returns {number} Similarity score (0-1)
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
    // DATA VALIDATION
    // ============================================
    
    /**
     * Sanitize string for safe display
     * @param {string} str - String to sanitize
     * @returns {string} Sanitized string
     */
    sanitize: function(str) {
        if (typeof str !== 'string') return '';
        return str.replace(/[<>]/g, '');
    },
    
    /**
     * Format timestamp to readable string
     * @param {number} timestamp - Unix timestamp
     * @returns {string} Formatted date/time
     */
    formatTimestamp: function(timestamp) {
        const date = new Date(timestamp);
        return date.toLocaleString();
    },
    
    /**
     * Deep clone object
     * @param {object} obj - Object to clone
     * @returns {object} Cloned object
     */
    deepClone: function(obj) {
        return JSON.parse(JSON.stringify(obj));
    }
};

// Make utilities globally available
if (typeof window !== 'undefined') {
    window.PhishGuardUtils = PhishGuardUtils;
}

console.log("PhishGuard Utils: Loaded");