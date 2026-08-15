document.addEventListener('DOMContentLoaded', () => {
    // --- 0. INCOGNITO CHECK ---
    chrome.extension.isAllowedIncognitoAccess((isAllowed) => {
        const warningEl = document.getElementById('incognito-warning');
        if (!isAllowed && warningEl) {
            warningEl.style.display = 'block';

            const btn = document.getElementById('btn-enable-incognito');
            if (btn) {
                btn.addEventListener('click', () => {
                    chrome.tabs.create({
                        url: 'chrome://extensions/?id=' + chrome.runtime.id
                    });
                });
            }
        }
    });

    // --- 1. SETTINGS & DNS SHIELD LOGIC ---
    const togglePreScan = document.getElementById('toggle-prescan');
    const toggleFortress = document.getElementById('toggle-fortress');
    const toggleShadow = document.getElementById('toggle-shadow');
    const toggleHttps = document.getElementById('toggle-https-upgrade');

    // Dynamic UI State Updater
    function updateDnsShieldUI(isActive) {
        const statusText = document.getElementById('status-text');
        const statusSub  = document.getElementById('status-sub');
        const statusDot  = document.getElementById('status-dot');
        const statusIcon = document.getElementById('status-icon');

        if (statusText) {
            statusText.textContent = isActive ? 'System Secure' : 'Shield Inactive';
        }
        if (statusSub) {
            statusSub.textContent = isActive ? 'Active' : 'Disabled';
            statusSub.style.color = isActive ? '#10b981' : '#f59e0b';
        }
        if (statusDot) {
            statusDot.style.background = isActive ? '#10b981' : '#f59e0b';
        }
        if (statusIcon) {
            statusIcon.className = isActive ? 'shield-wrap secure' : 'shield-wrap warning';
        }
    }

    function updateShadowProfileUI(_isActive) {
        // No separate desc element in compact layout — toggle visual handles it
    }

    // Load Settings (Layer 2)
    chrome.storage.local.get(['isDnsShieldActive', 'enablePreScan', 'enableFortress', 'logHistoryLimit', 'digital_dna_mode', 'httpsUpgradeEnabled', 'historyDisabled'], (result) => {
        let isDnsActive = true;
        if (result.isDnsShieldActive !== undefined) {
            isDnsActive = result.isDnsShieldActive === true;
        } else if (result.enablePreScan !== undefined) {
            isDnsActive = result.enablePreScan === true;
        }

        if (togglePreScan) {
            togglePreScan.checked = isDnsActive;
            updateDnsShieldUI(isDnsActive);
        }
        if (toggleFortress) toggleFortress.checked = result.enableFortress === true;
        
        const isShadowActive = result.digital_dna_mode === 'always';
        if (toggleShadow) {
            toggleShadow.checked = isShadowActive;
            updateShadowProfileUI(isShadowActive);
        }

        const limitInput = document.getElementById('history-limit');
        if (limitInput) {
            limitInput.value = result.logHistoryLimit || 20;
            if (result.historyDisabled) {
                // Hide the history limit container if history is disabled
                if (limitInput.parentElement) limitInput.parentElement.style.display = 'none';
            }
        }

        if (toggleHttps) toggleHttps.checked = result.httpsUpgradeEnabled === true;
    });

    // Save Settings Listeners (Step 1: Write to storage + Notify Service Worker)
    if (togglePreScan) {
        togglePreScan.addEventListener('change', () => {
            const val = togglePreScan.checked;
            chrome.storage.local.set({ isDnsShieldActive: val, enablePreScan: val });
            chrome.runtime.sendMessage({ type: "TOGGLE_DNS_SHIELD", enabled: val });
            updateDnsShieldUI(val);
        });
    }
    const limitInput = document.getElementById('history-limit');
    if (limitInput) {
        limitInput.addEventListener('change', () => {
            let val = parseInt(limitInput.value);
            if (val < 10) val = 10;
            if (val > 100) val = 100;
            chrome.storage.local.set({ logHistoryLimit: val });
            if (typeof Auth !== 'undefined' && Auth.syncSettings) Auth.syncSettings({ logHistoryLimit: val });
        });
    }

    if (toggleFortress) {
        toggleFortress.addEventListener('change', () => {
            const isEnabled = toggleFortress.checked;
            chrome.storage.local.set({ enableFortress: isEnabled });
            chrome.runtime.sendMessage({ type: "TOGGLE_FORTRESS", enabled: isEnabled });
            if (typeof Auth !== 'undefined' && Auth.syncSettings) Auth.syncSettings({ enableFortress: isEnabled });
        });
    }

    if (toggleShadow) {
        toggleShadow.addEventListener('change', () => {
            const isEnabled = toggleShadow.checked;
            const mode = isEnabled ? 'always' : 'auto';

            // Save state
            chrome.storage.local.set({ digital_dna_mode: mode });

            // Notify Background to Register/Unregister Script (Persistence)
            chrome.runtime.sendMessage({ type: "TOGGLE_SHADOW_PROFILE", enabled: isEnabled });

            updateShadowProfileUI(isEnabled);
        });
    }

    // HTTPS-Only Mode Toggle
    if (toggleHttps) {
        toggleHttps.addEventListener('change', () => {
            const enabled = toggleHttps.checked;

            // Save state directly from popup — do NOT rely on the background
            // to persist it, because the service worker may be asleep and the
            // message would fail silently leaving storage unchanged.
            chrome.storage.local.set({ httpsUpgradeEnabled: enabled }, () => {
                // After storage is saved, also tell the background to apply the rule
                chrome.runtime.sendMessage(
                    { action: 'toggleHttpsUpgrade', enabled },
                    () => { void chrome.runtime.lastError; } // consume any error
                );
            });
        });
    }

    // --- 2. ADMIN LOGIC (MOVED TO DASHBOARD) ---

    // --- 3. AUTHENTICATION LOGIC ---
    function initAuth() {
        if (typeof Auth === 'undefined') {
            setTimeout(initAuth, 100);
            return;
        }

        const btnLogin = document.getElementById('btn-login');
        const userProfileLink = document.getElementById('user-profile-link');
        const userInitial = document.getElementById('user-initial');
        const btnLogout = document.getElementById('btn-logout');

        // Check if essential elements exist
        if (!btnLogin || !userProfileLink) return;

        function updateAuthUI() {
            Auth.checkSession((user) => {
                if (user) {
                    // Logged In
                    btnLogin.style.display = 'none';
                    if (userProfileLink) userProfileLink.style.display = 'flex';

                    if (userInitial) {
                        const name = user.name || 'User';
                        userInitial.textContent = name.charAt(0).toUpperCase();
                    }
                    
                    const popupAvatar = document.getElementById('popup-avatar');
                    if (popupAvatar && user.avatar) {
                        popupAvatar.src = user.avatar;
                        popupAvatar.style.display = 'block';
                        if (userInitial) userInitial.style.display = 'none';
                    } else if (popupAvatar) {
                        popupAvatar.style.display = 'none';
                        if (userInitial) userInitial.style.display = 'block';
                    }

                    if (btnLogout) btnLogout.style.display = 'block';

                    // Explicitly Handle Profile Link Click to ensure Tab Open
                    userProfileLink.onclick = (e) => {
                        e.preventDefault();
                        chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
                    };

                    // Admin Access Check
                    const adminLink = document.getElementById('open-admin');
                    const OWNER = 'rajkumarpadhy2006@gmail.com';
                    if (adminLink && user.email.toLowerCase() === OWNER.toLowerCase()) {
                        adminLink.style.display = 'inline';
                    }
                } else {
                    // Logged Out
                    btnLogin.style.display = 'inline-block';
                    if (userProfileLink) userProfileLink.style.display = 'none';

                    if (btnLogout) btnLogout.style.display = 'none';
                }
            });
        }

        // Initial Check
        updateAuthUI();

        // Logout Listener
        if (btnLogout) {
            btnLogout.addEventListener('click', (e) => {
                e.preventDefault();
                if (confirm("Are you sure you want to log out?")) {
                    Auth.logout(() => {
                        updateAuthUI();
                    });
                }
            });
        }
    }

    initAuth();

    // Trigger Pending Syncs (XP, History, Settings)
    if (typeof Auth !== 'undefined') {
        setTimeout(() => {
            if (Auth.syncState) Auth.syncState();
            if (Auth.syncHistory) Auth.syncHistory();
        }, 2000);
    }

    // --- 4. STATS & GAMIFICATION ---
    function updateSafetyLevel() {
        // Trigger Sync to ensure fresh data
        chrome.runtime.sendMessage({ type: "SYNC_XP" });
        // Render current data immediately
        renderSafetyStats();
    }

    updateSafetyLevel();

    // Listen for live updates (e.g. after sync finishes)
    chrome.storage.onChanged.addListener((changes, area) => {
        if (area === 'local') {
            if (changes.userXP || changes.userLevel || changes.siteHistory) {
                // Determine if we need to redraw strictly (avoids loops if we are careful, but simple call is safe here)
                // We'll just read from storage again inside updateSafetyLevel
                // However, updateSafetyLevel triggers a sync, we should avoid infinite loops.
                // Actually updateSafetyLevel sends 'SYNC_XP', which does fetch -> storage.set.
                // storage.set triggers onChanged -> updateSafetyLevel -> SYNC_XP -> fetch.
                // This is a loop if server and client disagree constantly, but if they match, storage won't change?
                // Actually chrome.storage.set only triggers onChanged if value differs.
                // But let's be safe: separate the UI update from the Sync Trigger.

                // We will split updateSafetyLevel into renderSafetyStats() and the sync trigger.
                renderSafetyStats();
            }
        }
    });

    function renderSafetyStats() {
        chrome.storage.local.get(['siteHistory', 'userXP', 'userLevel'], (result) => {
            const history = result.siteHistory || [];
            const attacksBlocked = history.filter(h => h.score > 50).length;

            const xp = result.userXP || 0;
            const level = result.userLevel || 1;

            const levelEl = document.getElementById('safety-level');
            const xpEl = document.getElementById('safety-xp');
            const barEl = document.getElementById('xp-bar-fill');
            const blockedEl = document.getElementById('blocked-count');

            if (levelEl) levelEl.textContent = level;
            if (xpEl) xpEl.textContent = `${xp} XP`;
            if (blockedEl) blockedEl.textContent = attacksBlocked;

            if (barEl) {
                const nextLevelXp = Math.pow(level, 2) * 100;
                const prevLevelXp = Math.pow(level - 1, 2) * 100;

                let progress = 0;
                if (level === 1) {
                    progress = (xp / 100) * 100;
                } else {
                    progress = ((xp - prevLevelXp) / (nextLevelXp - prevLevelXp)) * 100;
                }
                barEl.style.width = `${Math.max(5, Math.min(progress, 100))}%`;
            }
        });
    }

    // --- 5. DOJO INIT ---
    if (typeof Dojo !== 'undefined') {
        Dojo.init();
    }

    // --- 6. GUEST TRACKING & DEBUG ---
    chrome.storage.local.get(['currentUser', 'stats_guest_count', 'visitLog'], (res) => {
        if (!res.currentUser) {
            const newCount = (res.stats_guest_count || 0) + 1;
            chrome.storage.local.set({ stats_guest_count: newCount });
        }
        // Update Log Count
        const logs = res.visitLog || [];
        const logCountEl = document.getElementById('debug-log-count');
        if (logCountEl) logCountEl.textContent = logs.length;
    });



    // --- 7. TRUST SYSTEM ---
    if (typeof ThreatIntel !== 'undefined') {
        chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
            if (tabs[0] && tabs[0].url) {
                const url = tabs[0].url;
                if (!url.startsWith('http')) {
                    const el = document.getElementById('trust-score-val');
                    if (el) el.textContent = 'N/A';
                    return;
                }

                // Update Domain Name Display
                const domainEl = document.getElementById('trust-domain');
                if (domainEl) {
                    try {
                        const hostname = new URL(url).hostname;
                        domainEl.textContent = hostname;
                    } catch (e) {
                        domainEl.textContent = "Current Site";
                    }
                }

                // Fetch Score with Timeout
                const fetchPromise = ThreatIntel.getTrustScore(url);
                const timeoutPromise = new Promise(resolve => setTimeout(() => resolve({ timeout: true }), 5000));

                const data = await Promise.race([fetchPromise, timeoutPromise]);
                const scoreDisplay = document.getElementById('trust-score-val');

                if (data && data.timeout) {
                    if (scoreDisplay) scoreDisplay.textContent = "Offline";
                } else if (data && scoreDisplay) {
                    if (data.score === null || data.votes === 0) {
                        scoreDisplay.textContent = "No Votes Yet";
                        scoreDisplay.style.color = '#6c757d'; // Gray
                    } else if (data.score >= 50) {
                        const voteText = data.votes === 1 ? 'vote' : 'votes';
                        scoreDisplay.textContent = `${data.score}% Safe (${data.votes} ${voteText})`;
                        scoreDisplay.style.color = '#28a745'; // Green
                    } else {
                        const voteText = data.votes === 1 ? 'vote' : 'votes';
                        scoreDisplay.textContent = `${100 - data.score}% Unsafe (${data.votes} ${voteText})`;
                        scoreDisplay.style.color = '#dc3545'; // Red
                    }
                } else if (scoreDisplay) {
                    scoreDisplay.textContent = "Offline";
                }

                // Bind Vote Buttons
                const btnSafe = document.getElementById('btn-vote-safe');
                const btnUnsafe = document.getElementById('btn-vote-unsafe');

                if (btnSafe) {
                    btnSafe.onclick = async () => {
                        btnSafe.innerHTML = "⏳";
                        const result = await ThreatIntel.vote(url, 'safe');
                        if (result.message) alert(result.message);
                        setTimeout(() => location.reload(), 100);
                    };
                }
                if (btnUnsafe) {
                    btnUnsafe.onclick = async () => {
                        btnUnsafe.innerHTML = "⏳";
                        const result = await ThreatIntel.vote(url, 'unsafe');
                        if (result.message) alert(result.message);
                        setTimeout(() => location.reload(), 100);
                    };
                }
            }
        });
    }

});
