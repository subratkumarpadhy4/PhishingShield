// Service Worker Window Polyfill for Firebase (Legacy support removed)
// Running on cloud backend (https://phishingshield.onrender.com)

let db = null; // No longer used

console.log("[PhishingShield] Service Worker Starting... " + new Date().toISOString());

// -----------------------------------------------------------------------------
// TRUSTED EXTENSIONS WHITELIST (Tier 1: Trusted)
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// TRUSTED EXTENSIONS WHITELIST (Tier 1: Trusted)
// -----------------------------------------------------------------------------
// Map of ID -> Name for extensions we explicitly trust.
const TRUSTED_EXTENSIONS = {
    "ghbmnnjooekpmoecnnnilnnbdlolhkhi": "Google Docs Offline",
    "kbfnbcaeplbcioakkpcpgfkobkghlhen": "Grammarly",
    "cfhdojbkjhnklbpkdaibdccddilifddb": "Adblock Plus",
    "cjpalhdlnbpafiamejdnhcphjbkeiagm": "uBlock Origin",
    "eimadpbcbfnmbkopoojfekhnkhdbieeh": "Dark Reader",
    "pkeeekfbjjpdkbngjolptfiedbfbcjoa": "LastPass", // Just examples, can be expanded
    // Add PhishingShield's own ID if known, though it won't check itself usually
};

// -----------------------------------------------------------------------------
// EXTENSION SCANNER LOGIC (Shared)
// -----------------------------------------------------------------------------
function checkExtensionRisk(extId, extInfo) {
    // 1. Check Whitelist (TIER: TRUSTED)
    if (TRUSTED_EXTENSIONS[extId]) {
        return { tier: 'TRUSTED', name: TRUSTED_EXTENSIONS[extId] };
    }

    // 2. Check Installation Type (TIER: CAUTION vs HIGH RISK)
    let tier = 'HIGH_RISK'; // Default fail-safe

    if (extInfo.installType === 'normal') {
        tier = 'CAUTION'; // Verified source (Web Store), but not in our Whitelist
    } else if (extInfo.installType === 'admin') {
        tier = 'CAUTION'; // Enterprise installed
    }

    return {
        tier: tier,
        name: extInfo.name,
        installType: extInfo.installType
    };
}

// -----------------------------------------------------------------------------
// ON INSTALL LISTENER (Real-time scanning)
// -----------------------------------------------------------------------------
if (chrome.management && chrome.management.onInstalled) {
    chrome.management.onInstalled.addListener((info) => {
        const result = checkExtensionRisk(info.id, info);
        console.log(`[PhishingShield] New Extension Installed: ${info.name} (${result.tier})`);

        if (result.tier === 'HIGH_RISK' || result.tier === 'CAUTION') {
            // 1. Notification
            const title = result.tier === 'HIGH_RISK' ? '🚨 High Risk Extension Detected' : '⚠️ Unverified Extension';
            const priority = result.tier === 'HIGH_RISK' ? 2 : 1;

            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'images/icon48.png',
                title: title,
                message: `"${info.name}" (${result.tier}) detected. Check Dashboard for details.`,
                priority: priority
            });

            // 2. Log to Dashboard (Storage)
            chrome.storage.local.get(['suspectedExtensions'], (data) => {
                const list = data.suspectedExtensions || [];
                // Add new entry
                list.push({
                    id: info.id,
                    name: info.name,
                    tier: result.tier,
                    installType: info.installType,
                    timestamp: Date.now()
                });
                chrome.storage.local.set({ suspectedExtensions: list });
            });
        }
    });
}

// -----------------------------------------------------------------------------
// CONTEXT MENU - REPORT WEBSITE
// -----------------------------------------------------------------------------
console.log("[PhishingShield] Initializing context menu module...");

// Create context menu item for reporting websites
function createContextMenu() {
    console.log("[PhishingShield] createContextMenu() called");

    // Check if contextMenus API is available
    if (!chrome.contextMenus) {
        console.error("[PhishingShield] contextMenus API not available - extension may not have permission");
        return;
    }

    // Attempt to create the menu item
    // We do NOT remove it first, to avoid race conditions.
    // If it exists, we catch the error.
    chrome.contextMenus.create({
        id: "report-to-phishingshield",
        title: "Report to PhishingShield",
        contexts: ["page", "link"]
    }, () => {
        if (chrome.runtime.lastError) {
            const msg = chrome.runtime.lastError.message;
            if (msg.includes("duplicate") || msg.includes("already exists")) {
                console.log("[PhishingShield] Context menu already registered (Perfectly fine).");
            } else {
                console.error("[PhishingShield] Context Menu Creation Error:", msg);
            }
        } else {
            console.log("[PhishingShield] ✅ Context menu created successfully!");
        }
    });
}

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId === "report-to-phishingshield") {
        console.log("[PhishingShield] Report context menu clicked");

        // Get the URL to report (either clicked link or current page)
        // info.linkUrl is available when right-clicking on a link
        // tab.url is available when right-clicking on the page
        const urlToReport = info.linkUrl || (tab && tab.url) || '';

        if (!urlToReport || urlToReport.startsWith('chrome://') || urlToReport.startsWith('chrome-extension://') || urlToReport.startsWith('edge://') || urlToReport.startsWith('moz-extension://')) {
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'images/icon48.png',
                title: 'Cannot Report',
                message: 'System pages cannot be reported.',
                priority: 2
            });
            return;
        }

        chrome.storage.local.get(['currentUser'], (data) => {
            const reporter = data.currentUser ? data.currentUser.email : 'Anonymous';
            const reporterDisplay = data.currentUser ? data.currentUser.name || reporter : 'Anonymous';

            let hostname;
            try {
                hostname = new URL(urlToReport).hostname;
            } catch (e) {
                hostname = urlToReport;
            }

            const reportPayload = {
                id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
                url: urlToReport,
                hostname: hostname,
                reporter: reporterDisplay,
                timestamp: Date.now(),
                status: 'pending'
            };

            // Send to Backend
            fetch('http://localhost:3000/api/reports', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(reportPayload)
            })
                .then(res => {
                    console.log("[PhishingShield] POST Response Status:", res.status);
                    return res.json();
            // TRY TO GET ANALYSIS FROM TAB FIRST
            function sendReport(analysisData = null) {
                const reportPayload = {
                    id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
                    url: urlToReport,
                    hostname: hostname,
                    reporter: reporterDisplay,
                    timestamp: Date.now(),
                    status: 'pending',
                    // Attach User's Local Analysis
                    aiAnalysis: analysisData ? {
                        score: analysisData.score || 0,
                        suggestion: (analysisData.score > 70) ? 'BAN' : (analysisData.score > 40 ? 'CAUTION' : 'IGNORE'),
                        reason: (analysisData.reasons || []).join(' | '),
                        timestamp: Date.now()
                    } : null
                };

                // Send to Backend (Localhost during Dev)
                fetch('http://localhost:3000/api/reports', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(reportPayload)
                })
                    .then(res => {
                        console.log("[PhishingShield] POST Response Status:", res.status);
                        return res.json();
                    })
                    .then(() => {
                        console.log("[PhishingShield] Report sent successfully!");

                        // Add XP to user
                        chrome.storage.local.get(['userXP', 'userLevel'], (data) => {
                            let xp = data.userXP || 0;
                            let level = data.userLevel || 1;
                            xp += 10; // 10 XP for reporting
                            updateXP(10); // Call updateXP with the amount
                        });

                        // NOTIFY USER OF SUCCESS
                        if (tab && tab.id) {
                            chrome.tabs.sendMessage(tab.id, {
                                type: "SHOW_NOTIFICATION",
                                title: "Report Sent!",
                                message: "Thank you for keeping the web safe.\n(+10 XP)"
                            })
                                .then(() => console.log("[PhishingShield] Toast Sent"))
                                .catch(() => {
                                    console.log("[PhishingShield] Content script inactive. Using fallback alert.");
                                    chrome.scripting.executeScript({
                                        target: { tabId: tab.id },
                                        func: () => alert("✅ Report Sent to PhishingShield!\n\nThank you for keeping the web safe.\n(+10 XP)")
                                    });
                                });
                        }
                    })
                    .catch(err => {
                        console.error("[PhishingShield] Report failed:", err);

                        // Notify failure
                        if (tab && tab.id) {
                            chrome.scripting.executeScript({
                                target: { tabId: tab.id },
                                func: (msg) => alert("⚠️ Report Failed: " + msg),
                                args: [err.message]
                            });
                        }
                    });
            }

            // Fetch Analysis from Content Script
            if (tab && tab.id) {
                chrome.tabs.sendMessage(tab.id, { type: "GET_RISK_ANALYSIS" }, (response) => {
                    if (chrome.runtime.lastError) {
                        console.log("[PhishingShield] Could not fetch analysis (Script blocked?), sending basic report.");
                        sendReport(null);
                    } else {
                        console.log("[PhishingShield] Got Analysis from Tab:", response);
                        sendReport(response);
                    }
                });
            } else {
                sendReport(null);
            }
        });
    }
});

// -----------------------------------------------------------------------------
// MESSAGE LISTENERS
// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------
// CONNECTION KEEP-ALIVE (Robust SW Lifespan)
// -----------------------------------------------------------------------------
chrome.runtime.onConnect.addListener((port) => {
    if (port.name === 'keepAlive') {
        console.log("[PhishingShield] Keep-Alive Connection Established");
        port.onDisconnect.addListener(() => {
            console.log("[PhishingShield] Keep-Alive Connection Closed - Client Disconnected");
        });
        // Optional: Send a heartbeat back periodically if really needed, but connection itself helps
    }
});

// -----------------------------------------------------------------------------
// MESSAGE LISTENERS
// -----------------------------------------------------------------------------
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    console.log("[PhishingShield] 🔵 Message received:", request.type, request);
    console.log("[PhishingShield] Service Worker is ACTIVE at:", new Date().toISOString());

    // PING to wake up service worker
    if (request.type === "PING") {
        console.log("[PhishingShield] PING received - Service Worker is awake");
        if (sendResponse) sendResponse({ success: true, awake: true });
        return true;
    }

    // 1. EXTENSION SECURITY CHECK (Async)
    if (request.type === "CHECK_EXTENSION_ID") {
        const extId = request.id;
        chrome.management.get(extId, (info) => {
            if (chrome.runtime.lastError) {
                console.warn(`[PhishingShield] Could not query extension ${extId}:`, chrome.runtime.lastError);
                sendResponse({ tier: 'HIGH_RISK', name: 'Unknown' });
                return;
            }
            const result = checkExtensionRisk(extId, info);
            sendResponse(result);
        });
        return true; // Keep channel open
    }

    // 2. LOG VISIT
    if (request.type === "LOG_VISIT") {
        console.log("[PhishingShield] LOG_VISIT handler triggered");
        console.log("[PhishingShield] LOG_VISIT data:", request.data);

        // Respond immediately to prevent timeout
        if (sendResponse) {
            sendResponse({ success: true });
        }

        // Award XP for visiting a website (async, but we already responded)
        console.log("[PhishingShield] Calling updateXP(5)");
        updateXP(5);

        // Save visit to log (async)
        chrome.storage.local.get(['visitLog'], (res) => {
            const logs = Array.isArray(res.visitLog) ? res.visitLog : [];
            // Keep last 200 entries for better history tracking
            if (logs.length > 200) logs.shift();
            if (request.data) {
                logs.push(request.data);
            }
            chrome.storage.local.set({ visitLog: logs }, () => {
                console.log("[PhishingShield] Visit log saved, total:", logs.length);
            });
        });

        return true; // Keep channel open for potential async response
    }

    // 3. ADD XP
    else if (request.type === "ADD_XP") {
        const amount = request.amount || 10;
        console.log("[PhishingShield] ADD_XP handler triggered, amount:", amount);
        updateXP(amount);
        if (sendResponse) sendResponse({ success: true });
        return true;
    }

    // 4. REPORT SITE (Async Fetch)
    else if (request.type === "REPORT_SITE") {

        // Fetch User Info first
        chrome.storage.local.get(['currentUser'], (data) => {
            const user = data.currentUser || {};
            const reporterDisplay = (user.name || 'Anonymous') + (user.email ? ` (${user.email})` : '');

            const reportPayload = {
                id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
                url: request.url,
                hostname: request.hostname,
                reporter: reporterDisplay,
                timestamp: Date.now(),
                status: 'pending'
            };

            // Send to Backend
            fetch('http://localhost:3000/api/reports', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(reportPayload)
            })
                .then(res => res.json())
                .then(data => {
                    console.log("[PhishingShield] Report Sent:", data);
                    sendResponse({ success: true, data: data });
                })
                .catch(err => {
                    console.error("[PhishingShield] Report Failed:", err);
                    sendResponse({ success: false, error: err.toString() });
                });

            // Local Backup
            chrome.storage.local.get(['reportedSites'], (res) => {
                const logs = res.reportedSites || [];
                logs.push(reportPayload);
                chrome.storage.local.set({ reportedSites: logs });
            });
        });

        return true; // Keep channel open for async fetch
    }

    // 5. UPDATE BLOCKLIST
    else if (request.type === "UPDATE_BLOCKLIST") {
        const bypassUrl = request.bypassUrl || null;
        // Clear cache to force fresh fetch
        blocklistCache.data = null;
        blocklistCache.timestamp = 0;
        updateBlocklistFromStorage(bypassUrl, function () {
            // Callback when blocklist update is complete
            if (sendResponse) sendResponse({ success: true, blocklistUpdated: true });
        }, true); // Force refresh
        return true; // Keep channel open for async response
    }

    // 7. FORCE BLOCKLIST SYNC (Immediate sync for ban/unban actions)
    else if (request.type === "FORCE_BLOCKLIST_SYNC") {
        console.log("[PhishingShield] Force blocklist sync requested");
        // Clear cache and force refresh
        blocklistCache.data = null;
        blocklistCache.timestamp = 0;
        updateBlocklistFromStorage(null, function () {
            if (sendResponse) sendResponse({ success: true, synced: true });
        }, true); // Force refresh
        return true;
    }

    // 6. SYNC XP (Force Sync from Frontend)
    else if (request.type === "SYNC_XP") {
        console.log("[PhishingShield] Forced XP Sync requested via message");
        syncXPToServer();
        if (sendResponse) sendResponse({ success: true });
        return true;
    }

    // 7. SCAN CONTENT WITH AI (Real-time)
    else if (request.type === "SCAN_CONTENT") {
        console.log("[PhishingShield] AI Scan Requested for:", request.url);

        // Fetch from Backend (Use LOCALHOST for testing)
        fetch('http://localhost:3000/api/ai/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                url: request.url,
                content: request.content
            })
        })
            .then(res => res.json())
            .then(data => {
                console.log("[PhishingShield] AI Scan Result:", data);
                // Send result back to the tab that requested it (or generic callback)
                if (sendResponse) sendResponse(data);
            })
            .catch(err => {
                console.error("[PhishingShield] AI Scan Failed:", err);
                if (sendResponse) sendResponse({ success: false, error: err.message });
            });

        return true; // Keep channel open
    }

    return true; // Default keep-open to be safe
});

/**
 * Simple and Reliable XP System
 */
function calculateLevel(xp) {
    return Math.floor(Math.sqrt(xp / 100)) + 1;
}

function updateXP(amount) {
    console.log("[PhishingShield] ========== updateXP CALLED ==========");
    console.log("[PhishingShield] Amount:", amount);

    if (amount === undefined || amount === null || amount === 0) {
        console.warn("[PhishingShield] Invalid XP amount:", amount);
        return;
    }

    // Show badge notification (different color for negative amounts)
    try {
        if (amount > 0) {
            chrome.action.setBadgeText({ text: `+${amount}` });
            chrome.action.setBadgeBackgroundColor({ color: '#28a745' });
        } else {
            chrome.action.setBadgeText({ text: `${amount}` });
            chrome.action.setBadgeBackgroundColor({ color: '#dc3545' });
        }
        setTimeout(() => chrome.action.setBadgeText({ text: "" }), 3000);
    } catch (e) {
        console.warn("[PhishingShield] Badge update failed:", e);
    }

    // Get current XP and update it
    console.log("[PhishingShield] Reading storage...");
    chrome.storage.local.get(['userXP', 'userLevel', 'users', 'currentUser'], (data) => {
        console.log("[PhishingShield] Storage data received:", data);
        // Initialize if not set
        let currentXP = typeof data.userXP === 'number' ? data.userXP : 0;
        let currentLevel = typeof data.userLevel === 'number' ? data.userLevel : 1;
        let users = Array.isArray(data.users) ? data.users : [];
        let currentUser = data.currentUser || null;

        // Add XP (can be negative for penalties)
        currentXP = currentXP + amount;
        // Ensure XP doesn't go below 0
        if (currentXP < 0) {
            currentXP = 0;
        }
        const newLevel = calculateLevel(currentXP);

        console.log("[PhishingShield] XP Update: " + (currentXP - amount) + " + " + amount + " = " + currentXP + " (Level " + newLevel + ")");

        // Check for level up
        if (newLevel > currentLevel) {
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'images/icon48.png',
                title: '🎉 Level Up!',
                message: `Congratulations! You reached Level ${newLevel}.`
            });

            // Broadcast to all tabs
            chrome.tabs.query({}, (tabs) => {
                tabs.forEach(tab => {
                    if (tab.id) {
                        chrome.tabs.sendMessage(tab.id, {
                            type: "LEVEL_UP",
                            level: newLevel
                        }).catch(() => { });
                    }
                });
            });
        }

        // Check for XP penalty (negative amount)
        if (amount < 0) {
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'images/icon48.png',
                title: '⚠️ XP Penalty Applied',
                message: `You lost ${Math.abs(amount)} XP for visiting a banned website.`
            });
        }

        // Prepare update object
        const updateData = {
            userXP: currentXP,
            userLevel: newLevel,
            pendingXPSync: true
        };

        // Update user in users array if logged in
        if (currentUser && currentUser.email) {
            const userIndex = users.findIndex(u => u && u.email === currentUser.email);
            if (userIndex >= 0) {
                users[userIndex].xp = currentXP;
                users[userIndex].level = newLevel;
                updateData.users = users;
            }
        }

        // Save to storage
        console.log("[PhishingShield] Saving to storage:", updateData);
        chrome.storage.local.set(updateData, () => {
            if (chrome.runtime.lastError) {
                console.error("[PhishingShield] ❌ FAILED to save XP:", chrome.runtime.lastError);
            } else {
                console.log("[PhishingShield] ✅ XP saved successfully:", currentXP);

                // -----------------------------------------------------------
                // [FIX] Trigger Immediate Sync
                // Replaces the old broken fetch('/api/reports') logic.
                // If amount is negative, flag as PENALTY so server accepts drop.
                // -----------------------------------------------------------
                syncXPToServer({ isPenalty: amount < 0 });
            }
        });
    });
    console.log("[PhishingShield] ========== updateXP EXIT ==========");
}

function updateSafeStreak(isCritical) {
    chrome.storage.local.get(['lastCriticalTime', 'safeStreak'], (result) => {
        if (isCritical) {
            chrome.storage.local.set({
                lastCriticalTime: Date.now(),
                safeStreak: 0,
                pendingXPSync: true // Sync the reset
            });
        }
    });
}

/**
 * Fortress Mode: Block 3rd Party Scripts
 */
function updateFortressRules(enabled) {
    const FORTRESS_RULE_ID = 999;

    if (enabled) {
        chrome.declarativeNetRequest.updateDynamicRules({
            addRules: [{
                "id": FORTRESS_RULE_ID,
                "priority": 10,
                "action": { "type": "block" },
                "condition": {
                    "resourceTypes": ["script"],
                    "domainType": "thirdParty"
                }
            }]
        }, () => {
            console.log("[PhishingShield] Fortress Mode: 3rd Party Scripts Blocked.");
        });
    } else {
        chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: [FORTRESS_RULE_ID]
        }, () => {
            console.log("[PhishingShield] Fortress Mode: Normal Script Access Restored.");
        });
    }
}

console.log("PhishingShield Service Worker Loaded - " + new Date().toISOString());

// Create context menu - this is critical for MV3
// Try to create immediately (for cases where extension was already installed)
// Wrap in try-catch to prevent service worker from crashing
try {
    createContextMenu();
} catch (e) {
    console.error("[PhishingShield] Error creating context menu on startup:", e);
}

// Create context menu on install/update - this is the primary way in MV3
chrome.runtime.onInstalled.addListener((details) => {
    console.log("[PhishingShield] Extension installed/updated:", details.reason);
    createContextMenu(); // Create context menu on install/update
});

// Also create on browser startup
chrome.runtime.onStartup.addListener(() => {
    console.log("[PhishingShield] Browser startup");
    createContextMenu(); // Recreate context menu on browser startup
});

// Initialize XP system on startup
chrome.storage.local.get(['userXP', 'userLevel'], (result) => {
    console.log("[PhishingShield] Startup - Current XP:", result.userXP, "Level:", result.userLevel);
    if (result.userXP === undefined || result.userXP === null) {
        chrome.storage.local.set({ userXP: 0, userLevel: 1 }, () => {
            console.log("[PhishingShield] ✅ XP system initialized to 0");
        });
    } else {
        console.log("[PhishingShield] XP system already initialized:", result.userXP);
    }
});

// Listen for storage changes to debug
chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === 'local' && changes.userXP) {
        console.log("[PhishingShield] 🔔 Storage changed - userXP:", changes.userXP.newValue, "(was:", changes.userXP.oldValue, ")");
    }
});

// Test function - call this from console to verify service worker is active
self.testServiceWorker = function () {
    console.log("[PhishingShield] ✅ Service Worker is ACTIVE!");
    chrome.storage.local.get(['userXP', 'userLevel'], (r) => {
        console.log("[PhishingShield] Current XP:", r.userXP, "Level:", r.userLevel);
    });
    return true;
};

/**
 * COMMUNITY BLOCKLIST
 * Converts 'banned' reports into active blocking rules.
 * Syncs with server to get global banned sites.
 */
// Cache for blocklist to reduce server calls
let blocklistCache = {
    data: null,
    timestamp: 0,
    TTL: 2000 // 2 seconds cache
};

function updateBlocklistFromStorage(bypassUrl = null, callback = null, forceRefresh = false) {
    // First get local banned sites and blacklist, and bypass tokens
    chrome.storage.local.get(['reportedSites', 'blacklist', 'bypassTokens'], (result) => {
        const reports = result.reportedSites || [];
        const blacklist = result.blacklist || [];
        let bypassTokens = result.bypassTokens || [];

        // Clean up old bypass tokens (older than 5 minutes or already used)
        const now = Date.now();
        bypassTokens = bypassTokens.filter(token => {
            // Remove tokens older than 5 minutes or already used
            return !token.used && (now - token.timestamp) < 5 * 60 * 1000;
        });

        // If a specific URL is being bypassed, ensure it's in the tokens
        if (bypassUrl) {
            const existingToken = bypassTokens.find(t => t.url === bypassUrl);
            if (!existingToken) {
                bypassTokens.push({
                    url: bypassUrl,
                    timestamp: now,
                    used: false
                });
            }
        }

        // Save cleaned up tokens
        chrome.storage.local.set({ bypassTokens: bypassTokens });

        let banned = reports.filter(r => r.status === 'banned');

        // Also add any URLs from blacklist array that aren't in reports
        blacklist.forEach(url => {
            if (!banned.find(r => r.url === url)) {
                try {
                    const hostname = new URL(url).hostname;
                    banned.push({
                        url: url,
                        hostname: hostname,
                        status: 'banned'
                    });
                } catch (e) {
                    // If URL parsing fails, use as-is
                    banned.push({
                        url: url,
                        hostname: url,
                        status: 'banned'
                    });
                }
            }
        });

        // Also fetch banned sites from server for global protection
        const API_BASE = 'https://phishingshield.onrender.com/api';
        const now = Date.now();

        // Use cache if available and not expired, unless force refresh
        if (!forceRefresh && blocklistCache.data && (now - blocklistCache.timestamp) < blocklistCache.TTL) {
            console.log("[PhishingShield] Using cached blocklist data");
            processBlocklist(blocklistCache.data, banned, bypassTokens, callback);
            return;
        }

        // Fetch fresh data from server
        fetch(`${API_BASE}/reports`)
            .then(res => res.json())
            .then(serverReports => {
                // Update cache
                blocklistCache.data = serverReports;
                blocklistCache.timestamp = now;

                processBlocklist(serverReports, banned, bypassTokens, callback);
            })
            .catch(err => {
                console.warn("[PhishingShield] Failed to fetch server blocklist, using local only:", err);
                // Fallback to local only
                processBlocklist([], banned, bypassTokens, callback);
            });
    });
}

// Helper function to process blocklist data
function processBlocklist(serverReports, banned, bypassTokens, callback) {
    const serverBanned = serverReports.filter(r => r.status === 'banned');

    // Merge local and server banned sites (deduplicate by URL)
    const bannedMap = new Map();
    banned.forEach(r => bannedMap.set(r.url, r));
    serverBanned.forEach(r => {
        if (!bannedMap.has(r.url)) {
            bannedMap.set(r.url, r);
        }
    });
    banned = Array.from(bannedMap.values());

    // Filter out URLs that have active bypass tokens
    // Match by both full URL and hostname for flexibility
    const activeBypassUrls = new Set();
    const activeBypassHostnames = new Set();
    bypassTokens.forEach(token => {
        activeBypassUrls.add(token.url);
        try {
            const urlObj = new URL(token.url);
            activeBypassHostnames.add(urlObj.hostname);
        } catch (e) {
            // If URL parsing fails, skip hostname
        }
    });

    banned = banned.filter(r => {
        // Check if URL matches
        if (activeBypassUrls.has(r.url)) return false;
        // Check if hostname matches
        try {
            const rHostname = r.hostname || new URL(r.url).hostname;
            if (activeBypassHostnames.has(rHostname)) return false;
        } catch (e) {
            // If parsing fails, continue
        }
        return true;
    });

    console.log(`[PhishingShield] Blocklist: ${banned.length} sites (${bypassTokens.length} bypassed)`);

    // Convert to Rules
    const newRules = banned.map((r, index) => {
        let hostname;
        try {
            hostname = r.hostname || new URL(r.url).hostname;
        } catch (e) {
            hostname = r.url;
        }

        return {
            "id": 2000 + index, // IDs 2000+ for Community Blocklist
            "priority": 1,
            "action": {
                "type": "redirect",
                "redirect": { "extensionPath": "/banned.html?url=" + encodeURIComponent(r.url) }
            },
            "condition": {
                "urlFilter": "||" + hostname,
                "resourceTypes": ["main_frame"]
            }
        };
    }).filter(rule => rule && rule.condition.urlFilter !== "||undefined"); // Filter invalid rules

    // Clear old 2000+ rules and add new ones
    chrome.declarativeNetRequest.getDynamicRules((currentRules) => {
        const removeIds = currentRules.filter(r => r.id >= 2000).map(r => r.id);
        chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: removeIds,
            addRules: newRules
        }, () => {
            console.log(`[PhishingShield] Blocklist Updated: ${newRules.length} sites blocked globally.`);
            if (callback) callback();
        });
    });
}

// Update on Startup
chrome.runtime.onStartup.addListener(updateBlocklistFromStorage);
chrome.runtime.onInstalled.addListener(updateBlocklistFromStorage);

// UPDATE_BLOCKLIST is handled in the main message listener above

// --- FAST BLOCKLIST SYNC (Every 3 seconds for near real-time updates) ---
// Note: Chrome alarms minimum is 1 minute, so we use setInterval for faster sync
let blocklistSyncInterval = null;

function startBlocklistSync() {
    // Clear any existing interval
    if (blocklistSyncInterval) {
        clearInterval(blocklistSyncInterval);
    }

    // Sync every 3 seconds
    blocklistSyncInterval = setInterval(() => {
        updateBlocklistFromStorage(null, () => {
            console.log("[PhishingShield] Blocklist synced (periodic - 3s)");
        });
    }, 3000); // 3 seconds
}

// Start the sync interval
startBlocklistSync();

// Also sync on tab activation to catch updates quickly
chrome.tabs.onActivated.addListener(() => {
    updateBlocklistFromStorage(null, () => {
        console.log("[PhishingShield] Blocklist synced (tab activated)");
    });
});

// -----------------------------------------------------------------------------
// BYPASS TOKEN MANAGEMENT - One-time bypass for banned sites
// -----------------------------------------------------------------------------

// Listen for tab updates to detect when user navigates to a bypassed URL
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    // Only process when navigation is complete (status === 'complete')
    if (changeInfo.status === 'complete' && tab.url) {
        chrome.storage.local.get(['bypassTokens'], (data) => {
            const tokens = data.bypassTokens || [];
            const activeTokens = tokens.filter(t => !t.used);

            // Check if this URL matches any active bypass token
            const matchingToken = activeTokens.find(token => {
                try {
                    const tokenUrl = new URL(token.url);
                    const currentUrl = new URL(tab.url);
                    // Match by hostname (allows navigation to any page on the domain)
                    return tokenUrl.hostname === currentUrl.hostname;
                } catch (e) {
                    // Fallback to exact URL match
                    return token.url === tab.url;
                }
            });

            if (matchingToken) {
                console.log('[PhishingShield] User navigated to bypassed URL:', tab.url);
                console.log('[PhishingShield] Marking bypass token as used (one-time use)');

                // Mark token as used
                matchingToken.used = true;
                matchingToken.usedAt = Date.now();

                // Save updated tokens
                chrome.storage.local.set({ bypassTokens: tokens }, () => {
                    // Rebuild blocklist to re-block this URL
                    console.log('[PhishingShield] Rebuilding blocklist - URL will be blocked again on next visit');
                    updateBlocklistFromStorage();
                });
            }
        });
    }
});

// -----------------------------------------------------------------------------
// XP SYNC (Global Leaderboard)
// -----------------------------------------------------------------------------

// Sync XP every 1 minute
chrome.alarms.create("syncXP", { periodInMinutes: 1 });

chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === "syncXP") {
        syncXPToServer();
    }
});

function syncXPToServer(customData = {}) {
    chrome.storage.local.get(['currentUser', 'userXP', 'userLevel', 'pendingXPSync'], (res) => {
        // Sync always if user is logged in (acts as heartbeat to fetch server updates like Admin Promotions)
        if (res.currentUser && res.currentUser.email) {
            console.log("[PhishingShield] Syncing XP to Global Leaderboard...");

            const userData = {
                ...res.currentUser,
                xp: res.userXP,
                level: res.userLevel,
                ...customData // Allow overrides like { isPenalty: true }
            };

            // Sync to server
            fetch("http://localhost:3000/api/users/sync", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(userData)
            })
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        console.log("[PhishingShield] ✅ XP Global Sync Successful");
                        chrome.storage.local.set({ pendingXPSync: false });

                        // 2-Way Sync: If Server has higher XP (e.g. Admin Promotion), update local
                        if (data.user && data.user.xp > res.userXP) {
                            console.log(`[PhishingShield] 📥 Server has higher XP (${data.user.xp} > ${res.userXP}). Updating local...`);
                            chrome.storage.local.set({
                                userXP: data.user.xp,
                                userLevel: data.user.level || calculateLevel(data.user.xp)
                            }, () => {
                                // Notify tabs to update HUD
                                chrome.tabs.query({}, (tabs) => {
                                    tabs.forEach(tab => {
                                        if (tab.id) chrome.tabs.sendMessage(tab.id, {
                                            type: "XP_UPDATE",
                                            xp: data.user.xp,
                                            level: data.user.level
                                        }).catch(() => { });
                                    });
                                });
                            });
                        }
                    }

                    // --- REPORT SELF-HEALING (Persistence) ---
                    // Check if my reports exist on server. If not (Wipe), re-upload.
                    syncReportsHeal();
                })
                .catch(e => console.error("[PhishingShield] ❌ XP Sync Failed:", e));
        }
    });
}

function syncReportsHeal() {
    chrome.storage.local.get(['reportedSites'], (res) => {
        const myReports = res.reportedSites || [];
        if (myReports.length === 0) return;

        fetch('http://localhost:3000/api/reports')
            .then(r => r.json())
            .then(serverReports => {
                const serverUrls = new Set(serverReports.map(r => r.url));

                myReports.forEach(localR => {
                    if (!serverUrls.has(localR.url)) {
                        console.warn(`[PhishingShield] Report missing on server (Wipe?): ${localR.url}. Re-uploading...`);
                        fetch('http://localhost:3000/api/reports', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(localR)
                        }).catch(e => console.error("Report Heal Failed", e));
                    }
                });
            })
            .catch(() => { });
    });
}
