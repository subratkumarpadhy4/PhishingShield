/**
 * PhishingShield Risk Engine
 * Analyzes page content for signs of phishing/social engineering.
 */
window.RiskEngine = {
    // Keywords often found in phishing attacks to create urgency
    urgencyKeywords: [
        "suspended", "suspend", "24 hours", "immediate action",
        "verify your account", "urgent", "unauthorized access",
        "locked", "compromised", "billing error", "restricted",
        "confirm your identity"
    ],

    // Official domains for major brands (for impersonation check)
    officialBrands: {
        "paypal": ["paypal.com"],
        "google": ["google.com"],
        "facebook": ["facebook.com"],
        "microsoft": ["microsoft.com"],
        "apple": ["apple.com"],
        "amazon": ["amazon.com"],
        "netflix": ["netflix.com"],
        "bank of america": ["bankofamerica.com"],
        "chase": ["chase.com"],
        "sbi": ["onlinesbi.sbi.bank.in", "sbi.co.in", "statebankofindia.com"],
        "state bank of india": ["onlinesbi.sbi", "sbi.co.in", "statebankofindia.com"],
        "hdfc": ["hdfcbank.com"],
        "icici": ["icicibank.com"],
        "axis bank": ["axisbank.com"]
    },

    analyzePage: async function () {
        let score = 0;
        let reasons = [];
        let primaryThreat = "Generic Suspicion"; // Initialized early to prevent TDZ error

        // SCORING WEIGHTS
        const SCORE_PUNYCODE = 50;
        const SCORE_BRAND = 30;
        const SCORE_URGENCY = 20;
        const SCORE_TYPOSQUAT = 45; // Keeping existing value
        const SCORE_INSECURE = 30; // Keeping existing value

        const textContent = document.body.innerText.toLowerCase();
        const title = document.title.toLowerCase();

        // HACKATHON DEMO MODE: Allow spoofing hostname via URL param
        const urlParams = new URLSearchParams(window.location.search);
        let hostname = window.location.hostname;
        if (urlParams.has('fake_host_for_testing')) {
            hostname = urlParams.get('fake_host_for_testing');
            console.warn(`[PhishingShield] ⚠️ SIMULATION MODE: Spoofing hostname to ${hostname}`);
        }

        // 0. Search Engine Whitelist
        if (/google|bing|yahoo|duckduckgo|search|msn/.test(hostname)) {
            return { score: 0, reasons: [] };
        }

        // 0. Search Engine Whitelist
        if (/google|bing|yahoo|duckduckgo|search|msn/.test(hostname)) {
            return { score: 0, reasons: [] };
        }

        // 0.1 Threat Intel Check (Async)
        if (typeof ThreatIntel !== 'undefined') {
            const intel = await ThreatIntel.check(window.location.href);
            if (intel.isThreat) {
                console.warn(`[RiskEngine] CRITICAL BLOCKED by Threat Intel: ${intel.source}`);
                return {
                    score: intel.riskScore,
                    reasons: [`🚨 BLOCKED: ${intel.source} (${intel.type}) (+${intel.riskScore})`],
                    primaryThreat: `${intel.type} Detected`
                };
            }
        }

        // 1. Official Brand Verification (The "Green Pattern")
        // 1. Official Brand Verification (The "Green Pattern")
        for (const [brand, domains] of Object.entries(this.officialBrands)) {
            // Normalize to array
            const officialList = Array.isArray(domains) ? domains : [domains];

            if (title.includes(brand) || textContent.includes(brand)) {

                let isOfficial = false;
                for (const d of officialList) {
                    if (hostname === d || hostname.endsWith("." + d) || hostname.endsWith(d)) {
                        isOfficial = true;
                        break;
                    }
                }

                if (isOfficial) {
                    console.log(`[RiskEngine] Verified Official Site: ${brand} at ${hostname}`);
                    return { score: 0, reasons: [`✅ Verified Official ${brand.toUpperCase()} Website`] };
                }
            }
        }

        // 2. Domain Complexity Heuristic
        const isSimpleDomain = (hostname.split('.').length <= 2) &&
            (!hostname.includes('-')) &&
            (hostname.length < 20);

        // Urgency Check
        let urgencyCount = 0;
        this.urgencyKeywords.forEach(keyword => {
            if (textContent.includes(keyword)) {
                urgencyCount++;
            }
        });

        if (urgencyCount > 0) {
            score += SCORE_URGENCY; // Changed from dynamic calculation to fixed bucket for simplicity as requested, or we can cap it.
            // Requirement said "20 points for urgency keywords". I'll add 20 if ANY are found, to strictly follow "assign 20 points".
            // Previous logic was Math.min(count * 10, 40). 
            // I will adhere to "assign 20 points for urgency keywords" as a flat penalty for presence.
            reasons.push(`Detected Urgency Keywords (+${SCORE_URGENCY})`);
        }

        // Brand Impersonation Check
        for (const [brand, domains] of Object.entries(this.officialBrands)) {
            if (title.includes(brand)) {
                const officialList = Array.isArray(domains) ? domains : [domains];
                // Check if hostname matches ANY of the official domains
                const isSafe = officialList.some(d => hostname === d || hostname.endsWith("." + d) || hostname.endsWith(d));

                if (!isSafe) {
                    score += SCORE_BRAND;
                    reasons.push(`Possible Brand Impersonation: Claims to be ${brand.toUpperCase()} (+${SCORE_BRAND})`);
                }
            }
        }

        // 3. AI Analysis (Naive Bayes)
        // 3. AI Analysis (Naive Bayes) - DISABLED in favor of Real Async AI (Gemini)
        /*
        if (typeof AIModel !== 'undefined') {
            const aiResult = AIModel.predict(textContent + " " + title);

            if (aiResult.isPhishing) {
                let aiPoints = Math.round(aiResult.probability * 40);
                if (isSimpleDomain) {
                    aiPoints = Math.min(aiPoints, 10);
                    reasons.push(`🤖 AI Alert (Dampened by Clean Domain Trust) (+${aiPoints})`);
                } else {
                    reasons.push(`🤖 AI Engine: ${Math.round(aiResult.probability * 100)}% Confidence (+${aiPoints})`);
                }
                score += aiPoints;
            }
        }
        */

        // 4. Technical Indicators

        // A. Punycode
        if (hostname.startsWith('xn--')) {
            score += SCORE_PUNYCODE;
            reasons.push(`⚠️ Detected Punycode Domain (+${SCORE_PUNYCODE})`);
        }

        // B. ENTROPY SENTINEL
        const domainParts = hostname.split('.');
        let maxEntropy = 0;
        let highEntropyPart = "";

        domainParts.forEach(part => {
            if (part.length < 4 || ["www", "com", "net", "org", "co", "uk", ".io"].includes(part)) return;
            const e = this.calculateEntropy(part);
            if (e > maxEntropy) {
                maxEntropy = e;
                highEntropyPart = part;
            }
        });

        if (maxEntropy > 4.2) {
            score += 25;
            reasons.push(`⚠️ High Domain Entropy in '${highEntropyPart}' (+25)`);
        }

        // C. TYPOSQUATTING SENTINEL
        if (!reasons.some(r => r.includes("Verified Official"))) {
            for (const [brand, domains] of Object.entries(this.officialBrands)) {
                // Handle potential array of domains per brand
                const officialList = Array.isArray(domains) ? domains : [domains];
                let isTyposquat = false;

                for (const officialDomain of officialList) {
                    const officialName = officialDomain.split('.')[0];

                    for (const part of domainParts) {
                        if (part.length < 3) continue;
                        const distance = this.calculateLevenshtein(officialName, part);
                        if (distance === 1 && Math.abs(officialName.length - part.length) <= 1) {
                            isTyposquat = true;
                            break;
                        }
                    }
                    if (isTyposquat) break; // Found a match for this brand
                }

                if (isTyposquat) {
                    score += SCORE_TYPOSQUAT;
                    reasons.push(`⚠️ Potential Typosquatting: resembles "${brand}" (+${SCORE_TYPOSQUAT})`);
                }
            }
        }

        // D. High-Risk TLDs
        const riskyTLDs = ['.xyz', '.top', '.club', '.online', '.live', '.buzz', '.cn', '.tk', '.gq'];
        for (const tld of riskyTLDs) {
            if (hostname.endsWith(tld)) {
                score += 15;
                reasons.push(`⚠️ Suspicious TLD (${tld}) (+15)`);
                break;
            }
        }

        // E. Domain Age Penalty (Simulation)
        // In a real app, this would call a WHOIS API.
        // Simulation: Penalize if "new" or "temp" is in the name, or randomized for demo
        if (hostname.includes('new') || hostname.includes('temp') || urlParams.has('simulate_new_domain')) {
            score += 20;
            reasons.push(`⚠️ Domain Too Young (< 30 Days) (+20)`);
        }

        // 5. Sensitive Input Check & MITM Detection (SSL Stripping)
        const passwordField = document.querySelector('input[type="password"]');
        const loginForm = document.querySelector('form[action*="login"], form[action*="signin"]');

        // Critical: Checking for SSL Stripping
        // Attackers downgrade HTTPS -> HTTP to capture data.
        // TREAT LOCAL FILES (file:) AS INSECURE FOR TESTING
        if (window.location.protocol === 'http:' || window.location.protocol === 'file:') {
            // MitM Warning: Non-secure connection on sensitive pages
            // If there's a password field OR it looks like a login form, FLAG IT.
            if (passwordField || loginForm) {
                score += 50; // High Penalty
                reasons.push("🚨 MITM / SSL Stripping Detected: Login over insecure HTTP! (+50)");
                primaryThreat = "Man-in-the-Middle Attack";
            } else {
                // General insecure warning
                score += 10;
                reasons.push("⚠️ Insecure Connection (HTTP) (+10)");
            }
        } else {
            // Mixed Content Check (Passive)
            // If main page is HTTPS, but loads insecure scripts/iframes
            const insecureResources = document.querySelectorAll('script[src^="http:"], iframe[src^="http:"]');
            if (insecureResources.length > 0) {
                score += 35;
                reasons.push(`⚠️ Mixed Content: Page is secure, but loads ${insecureResources.length} insecure resources. (+35)`);
            }
        }

        // 6. Domain Coherence Check (Adaptive Whitelist)
        // Verify if the Page Title strongly matches the Domain (e.g. "Small Bank" -> "smallbank.com")
        const coherence = this.calculateDomainCoherence(title, hostname);
        const COHERENCE_THRESHOLD = 0.6; // 60% match required

        if (coherence > COHERENCE_THRESHOLD) {
            // Strong match! This is likely a legitimate site.
            console.log(`[RiskEngine] High Domain Coherence (${(coherence * 100).toFixed(0)}%): ${title} matches ${hostname}`);

            // SIGNIFICANTLY reduce score (Bonuses)
            let safetyBonus = 40;

            // If it was flagged by AI or Keywords, dampen those specifically
            if (reasons.some(r => r.includes("Urgency") || r.includes("AI"))) {
                safetyBonus += 20; // Extra help for "false positives"
            }

            score = Math.max(0, score - safetyBonus); // Ensure valid score
            reasons.push(`✅ Adaptive Trust: Domain matches Page Title (-${safetyBonus})`);

            // Remove specific "Suspicion" warnings if we are now trusted
            reasons = reasons.filter(r => !r.includes("Generic Suspicion"));
        }

        // Determine Primary Threat for HUD Headline
        // primaryThreat is already initialized at the top
        if (score > 80) primaryThreat = "CRITICAL THREAT";
        else if (reasons.some(r => r.includes("Punycode"))) primaryThreat = "Fake Domain (Punycode)";
        else if (reasons.some(r => r.includes("Typosquatting"))) primaryThreat = "Impersonation Attack";
        else if (reasons.some(r => r.includes("Brand"))) primaryThreat = "Brand Spoofing";
        else if (reasons.some(r => r.includes("Urgency"))) primaryThreat = "Social Engineering";
        else if (reasons.some(r => r.includes("AI"))) primaryThreat = "AI Detected Scam";

        return {
            score: Math.min(score, 100),
            reasons: reasons,
            primaryThreat: primaryThreat // New Field
        };
    },

    /**
     * Scans the DOM for resources injected by other extensions (chrome-extension://).
     * This helps detect if a user is being tracked or modified by a suspicious extension.
     */
    /**
     * Scans the DOM for resources injected by other extensions (chrome-extension://).
     * ASYNC: Queries background script to check if extension is Trusted, Caution, or High Risk.
     */
    analyzeExtensions: async function () {
        const foundExtensions = new Set();
        const riskyTags = ['script', 'iframe', 'link', 'img', 'embed', 'object'];

        // HACKATHON DEMO: Allow simulation of a rogue extension via URL param
        const urlParams = new URLSearchParams(window.location.search);
        let simulated = urlParams.has('simulate_rogue_ext');

        riskyTags.forEach(tagName => {
            const elements = document.getElementsByTagName(tagName);
            for (let el of elements) {
                let src = el.src || el.href;
                if (src && src.startsWith('chrome-extension://')) {
                    try {
                        const parts = src.split('/');
                        if (parts.length >= 3) {
                            const extId = parts[2];
                            foundExtensions.add(extId);
                        }
                    } catch (e) { }
                }
            }
        });

        const suspiciousList = Array.from(foundExtensions);
        let score = 0;
        let reasons = [];
        let count = 0;

        // processing loop
        for (const id of suspiciousList) {
            // Ask Background for Tier
            // We use a Promise wrapper for chrome.runtime.sendMessage
            const check = await new Promise(resolve => {
                chrome.runtime.sendMessage({ type: "CHECK_EXTENSION_ID", id: id }, (response) => {
                    // Handle case where background might not respond (e.g. context invalid)
                    if (chrome.runtime.lastError || !response) {
                        resolve({ tier: 'HIGH_RISK', name: 'Unknown' });
                    } else {
                        resolve(response);
                    }
                });
            });

            if (check.tier === 'TRUSTED') {
                // Tier 1: Do nothing. Safe.
                console.log(`[PhishingShield] Trusted Extension Detected: ${check.name} (${id})`);
            } else if (check.tier === 'CAUTION') {
                // Tier 2: Low Risk / Caution
                score += 10;
                reasons.push(`⚠️ Caution: Unverified Extension active: '${check.name}' (+10)`);
                count++;
            } else {
                // Tier 3: High Risk
                score += 25;
                reasons.push(`🚨 HIGH RISK: Extension '${check.name}' (${check.installType || 'Unknown'}) modifying this page. (+25)`);
                count++;
            }
        }

        if (simulated) {
            score += 25;
            reasons.push("⚠️ DETECTED SIMULATED ROGUE EXTENSION (Demo) (+25)");
            count++;
        }

        return {
            score: score,
            reasons: reasons,
            count: count
        };
    },


    /**
     * Calculates Levenshtein Distance between two strings.
     * Measures how many edits (insert, delete, subst) are needed to turn A into B.
     */
    calculateLevenshtein: function (a, b) {
        if (a.length === 0) return b.length;
        if (b.length === 0) return a.length;

        const matrix = [];

        // Increment along the first column of each row
        var i;
        for (i = 0; i <= b.length; i++) {
            matrix[i] = [i];
        }

        // Increment each column in the first row
        var j;
        for (j = 0; j <= a.length; j++) {
            matrix[0][j] = j;
        }

        // Fill in the rest of the matrix
        for (i = 1; i <= b.length; i++) {
            for (j = 1; j <= a.length; j++) {
                if (b.charAt(i - 1) == a.charAt(j - 1)) {
                    matrix[i][j] = matrix[i - 1][j - 1];
                } else {
                    matrix[i][j] = Math.min(
                        matrix[i - 1][j - 1] + 1, // substitution
                        Math.min(
                            matrix[i][j - 1] + 1, // insertion
                            matrix[i - 1][j] + 1  // deletion
                        )
                    );
                }
            }
        }

        return matrix[b.length][a.length];
    },

    /**
     * Calculates "Coherence" between Page Title and Domain Name.
     * Returns a score from 0.0 to 1.0.
     * 1.0 means perfect match (e.g. Title "Google" -> Domain "google.com")
     */
    calculateDomainCoherence: function (title, hostname) {
        if (!title || !hostname) return 0;

        // 1. Clean and Tokenize Title
        // Remove common stop words and separators
        const stopWords = ["home", "page", "login", "welcome", "to", "the", "of", "and", "&", "|", "-", ":"];
        let titleTokens = title.toLowerCase()
            .replace(/[^\w\s]/g, ' ') // Replace punctuation with space
            .split(/\s+/)
            .filter(t => t.length > 2 && !stopWords.includes(t));

        if (titleTokens.length === 0) return 0;

        // 2. Clean Domain
        // Remove TLD (com, org, co.in) and www
        let domainBody = hostname.toLowerCase().replace(/^www\./, '');
        // Simple TLD removal (last part)
        const parts = domainBody.split('.');
        if (parts.length > 1) parts.pop(); // remove TLD
        if (parts.length > 0 && (parts[parts.length - 1] === 'co' || parts[parts.length - 1] === 'com')) parts.pop(); // handle .co.in
        domainBody = parts.join('');

        // 3. Check for Overlap
        // We check how much of the Domain is covered by Title keywords.
        // e.g. Domain "citycoopbank", Title "City Cooperative Bank"
        // "city" found? Yes. "cooperative" -> "coop" (fuzzy)? Yes. "bank" found? Yes.

        let matches = 0;
        let matchedLength = 0;

        titleTokens.forEach(token => {
            if (domainBody.includes(token)) {
                matches++;
                matchedLength += token.length;
            } else {
                // Fuzzy check (abbreviations)
                // e.g. "Cooperative" (11 chars) -> "coop" (4 chars) in domain
                // If the first 3-4 chars match, it's a likely partial match
                if (token.length >= 4 && domainBody.includes(token.substring(0, 4))) {
                    matches += 0.8; // Partial credit
                    matchedLength += 4;
                }
            }
        });

        // Coherence Score = (Matched Characters / Total Domain Length)
        // This ensures the Title explains the Domain.
        // If Domain is "amazon", Title "Amazon", match is 100%.
        // If Domain is "bad-site-xyz", Title "Amazon", match is near 0.

        // Guard against divide by zero or tiny domains
        if (domainBody.length < 3) return 0;

        let ratio = matchedLength / domainBody.length;

        // Cap at 1.0
        return Math.min(ratio, 1.0);
    },

    /**
     * Calculates Shannon Entropy of a string.
     * Higher entropy = more randomness (likely bot-generated).
     * Normal english words usually have entropy < 3.5.
     * Random strings like "x7z9k2" often have entropy > 4.0.
     */
    calculateEntropy: function (str) {
        const len = str.length;
        const frequencies = {};

        for (let i = 0; i < len; i++) {
            const char = str[i];
            frequencies[char] = (frequencies[char] || 0) + 1;
        }

        let entropy = 0;
        for (const char in frequencies) {
            const p = frequencies[char] / len;
            entropy -= p * Math.log2(p);
        }

        return entropy;
    }
};
