// Toggle this for development
if (typeof window.DEV_MODE === 'undefined') {
    window.DEV_MODE = false;
}
if (typeof window.API_BASE === 'undefined') {
    window.API_BASE = window.DEV_MODE ? "http://localhost:3000/api" : "https://oculus-eight.vercel.app/api";
}

var DEV_MODE = window.DEV_MODE;
var API_BASE = window.API_BASE;

console.log(`[DASHBOARD] Running in ${DEV_MODE ? 'DEVELOPMENT' : 'PRODUCTION'} mode`);
console.log(`[DASHBOARD] API Base: ${API_BASE}`);

document.addEventListener('DOMContentLoaded', () => {
    try {
        console.log("Dashboard: Initializing...");

        // 0. ADMIN SECURITY CHECK
        checkAdminAccess();

        // 1. NAVIGATION TABS
        const navLinks = document.querySelectorAll('.nav-item');
        const tabs = document.querySelectorAll('.tab-content');
        const pageTitle = document.getElementById('page-title');

        if (navLinks.length > 0) {
            navLinks.forEach(link => {
                link.addEventListener('click', (e) => {
                    e.preventDefault();

                    const updateTabState = () => {
                        // Remove Active Class from all
                        navLinks.forEach(l => l.classList.remove('active'));
                        tabs.forEach(t => t.classList.remove('active'));

                        // Add Active to Clicked
                        link.classList.add('active');
                        const tabId = link.getAttribute('data-tab');
                        const tab = document.getElementById(tabId);
                        if (tab) tab.classList.add('active');

                        // Update Title
                        if (pageTitle) {
                            let text = link.innerText.trim();
                            // Remove emoji prefix if present (likely 2 chars + space)
                            if (text.length > 3) text = text.substring(2).trim();
                            pageTitle.textContent = text;
                        }
                        console.log("Tab Switched to:", tabId);
                    };

                    // Use View Transitions API if available for smooth React-like feel
                    if (document.startViewTransition) {
                        document.startViewTransition(() => {
                            updateTabState();
                        });
                    } else {
                        updateTabState();
                    }
                });
            });
        }

        const viewAllBtn = document.getElementById('view-all-users');
        if (viewAllBtn) {
            viewAllBtn.addEventListener('click', () => {
                const usersTab = document.querySelector('[data-tab="users"]');
                if (usersTab) usersTab.click();
            });
        }

        // 2. DATE
        const dateEl = document.getElementById('current-date');
        if (dateEl) {
            dateEl.textContent = new Date().toLocaleDateString('en-US', {
                weekday: 'long', year: 'numeric', month: 'long', day: 'numeric'
            });
        }

        // 3. LOAD DATA & STATS
        // 3. LOAD DATA & STATS
        function renderDashboardUI() {
            // Force Sync with Backend on Load to get latest XP
            chrome.runtime.sendMessage({ type: "SYNC_XP" });

            if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
                chrome.storage.local.get(['visitLog', 'theme', 'users', 'suspectedExtensions', 'userXP', 'userLevel'], (result) => {
                    let log = result.visitLog;
                    if (!Array.isArray(log)) log = [];

                    const users = result.users || [];
                    const extLog = result.suspectedExtensions || [];

                    updateStats(log);
                    renderTable(log);
                    renderExtensionTable(extLog); // New Function
                    renderUserThreatsTable(log);  // NEW: Weekly Threats
                    renderLeaderboard(users);

                    if (result.theme === 'dark') {
                        document.body.classList.add('dark-theme');
                        const themeBtn = document.getElementById('theme-toggle');
                        if (themeBtn) themeBtn.innerText = '☀️';
                    }
                });
            } else {
                console.warn("Chrome Storage not available.");
            }
        }

        // Initial Render (Local Data)
        renderDashboardUI();

        // Fetch Global Data (Background Sync)
        if (typeof Auth !== 'undefined' && Auth.getUsers) {
            Auth.getUsers((users) => {
                console.log("[Dashboard] Global users fetched:", users.length);

                // CRITICAL FIX: Sync "My Profile" with Global Data, but respect timestamps
                chrome.storage.local.get(['currentUser', 'userXP', 'lastXpUpdate'], (res) => {
                    if (res.currentUser && res.currentUser.email) {
                        const meInGlobal = users.find(u => u.email === res.currentUser.email);
                        if (meInGlobal) {
                            const globalTime = Number(meInGlobal.lastUpdated) || 0;
                            const localTime = Number(res.lastXpUpdate) || 0;

                            // Only update if global is NEWER (prevents reverting admin edits)
                            if (globalTime > localTime) {
                                console.log(`[Dashboard] Global is newer (${globalTime} > ${localTime}). Syncing XP: ${res.userXP} -> ${meInGlobal.xp}`);
                                // Update Local Storage (This triggers the UI re-render listener)
                                chrome.storage.local.set({
                                    userXP: meInGlobal.xp,
                                    userLevel: meInGlobal.level || 1,
                                    lastXpUpdate: globalTime, // Update timestamp
                                    currentUser: { ...res.currentUser, ...meInGlobal } // Merge Update
                                });
                            } else {
                                console.log(`[Dashboard] Local is newer (${localTime} >= ${globalTime}). Keeping local XP: ${res.userXP} (preventing revert of admin edit)`);
                            }
                        }
                    }
                });
            });
        }

        // Listen for storage changes to update in real-time
        if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.onChanged) {
            chrome.storage.onChanged.addListener((changes, areaName) => {
                if (areaName === 'local') {
                    // Update if visitLog, userXP, userLevel, or users changed
                    if (changes.visitLog || changes.userXP || changes.userLevel || changes.users) {
                        renderDashboardUI();
                    }
                }
            });
        }

        // 4. AUTH & PROFILE
        initDashboardAuth();
        initProfileModal();

        // 5. ADMIN PASSKEY INPUT
        // 5. ADMIN ACCESS CHECK (OWNER ONLY)
        const OWNER_EMAIL = 'rajkumarpadhy2006@gmail.com';

        // We check session, if user is Owner, we show the link
        Auth.checkSession((user) => {
            if (user && user.email.toLowerCase() === OWNER_EMAIL.toLowerCase()) {
                const al = document.getElementById('open-admin');
                const pi = document.getElementById('admin-passkey');
                if (al) {
                    al.style.display = 'inline';
                    al.innerText = '👑 Admin Panel';
                }
                if (pi) pi.style.display = 'none'; // Hide passkey input, not needed
            }
        });

        // 6. ACTION LISTENERS
        const exportBtn = document.getElementById('export-pdf');
        if (exportBtn) {
            exportBtn.addEventListener('click', () => {
                generateAndPrintReport();
            });
        }

        const themeToggle = document.getElementById('theme-toggle');
        if (themeToggle) {
            themeToggle.addEventListener('click', () => {
                const isDark = document.body.classList.toggle('dark-theme');
                themeToggle.innerText = isDark ? '☀️' : '🌙';
                chrome.storage.local.set({ theme: isDark ? 'dark' : 'light' });
            });
        }

        const clearBtn = document.getElementById('clear-history');
        if (clearBtn) {
            document.getElementById('clear-history').addEventListener('click', () => {
                if (confirm('Clear all history? This cannot be undone.')) {
                    chrome.storage.local.set({ visitLog: [], siteHistory: [] }, () => {
                        location.reload();
                    });
                }
            });
        }

        const refreshBtn = document.getElementById('refresh-log');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                refreshBtn.textContent = 'Refreshing...';
                // Reload storage data
                chrome.storage.local.get(['visitLog'], (result) => {
                    try {
                        let log = result.visitLog;
                        if (!Array.isArray(log)) {
                            console.warn("Invalid visitLog format, resetting to empty array.");
                            log = [];
                        }

                        // Update Stats & Table
                        updateStats(log);
                        renderTable(log);
                    } catch (e) {
                        console.error("Refresh failed:", e);
                    } finally {
                        setTimeout(() => {
                            refreshBtn.textContent = 'Refresh';
                        }, 500);
                    }
                });
            });
        }

    } catch (err) {
        console.error("Dashboard Critical Error:", err);
    }

    // LISTENER: My Reports Refresh
    const refreshReportsBtn = document.getElementById('refresh-my-reports');
    if (refreshReportsBtn) {
        refreshReportsBtn.addEventListener('click', () => {
            refreshReportsBtn.textContent = 'Refreshing...';
            loadUserReports();
            setTimeout(() => refreshReportsBtn.textContent = '🔄 Refresh Status', 1000);
        });
    }

    // --- HELPER: Handle Refresh Button State ---
    const handleRefresh = async (btn, actionFn) => {
        if (!btn || btn.disabled) return;

        // 1. Start Spin
        btn.disabled = true;

        // Use innerHTML to keep structure
        btn.innerHTML = `<span class="icon rotating">🔄</span> Refreshing...`;
        btn.style.color = 'var(--primary)';

        try {
            // 2. Execute Action (min 800ms for visual feel)
            const start = Date.now();
            await actionFn();
            const elapsed = Date.now() - start;
            if (elapsed < 800) await new Promise(r => setTimeout(r, 800 - elapsed));

            // 3. Success Feedback
            btn.innerHTML = `✅ Updated`;
            btn.style.color = 'var(--success)';
            btn.style.borderColor = 'var(--success)';

        } catch (e) {
            console.error("Refresh Error:", e);
            btn.innerHTML = `❌ Error`;
            btn.style.color = 'var(--danger)';
        } finally {
            // 4. Reset after delay
            setTimeout(() => {
                btn.innerHTML = `<span class="icon">🔄</span> Refresh`;
                btn.style.color = 'var(--secondary)';
                btn.style.borderColor = 'var(--border-color)';
                btn.disabled = false;
            }, 1500);
        }
    };

    // LISTENER: Leaderboard Refresh
    const refreshLeaderboardBtn = document.getElementById('refresh-leaderboard');
    if (refreshLeaderboardBtn) {
        refreshLeaderboardBtn.addEventListener('click', () => {
            handleRefresh(refreshLeaderboardBtn, () => {
                return new Promise((resolve) => {
                    // Timeout safety for network requests
                    let done = false;
                    const safeResolve = () => { if (!done) { done = true; resolve(); } };
                    setTimeout(() => safeResolve(), 5000); // Max 5s wait

                    if (typeof Auth !== 'undefined' && Auth.getUsers) {
                        Auth.getUsers((users) => {
                            if (users && users.length) {
                                renderLeaderboard(users);
                                chrome.storage.local.set({ users: users });
                            }
                            safeResolve();
                        });
                    } else {
                        // Fallback
                        chrome.storage.local.get(['users'], (res) => {
                            renderLeaderboard(res.users || []);
                            safeResolve();
                        });
                    }
                });
            });
        });
    }

    // LISTENER: Threats Refresh
    const refreshThreatsBtn = document.getElementById('refresh-threats');
    if (refreshThreatsBtn) {
        refreshThreatsBtn.addEventListener('click', () => {
            handleRefresh(refreshThreatsBtn, () => {
                return new Promise((resolve) => {
                    chrome.storage.local.get(['visitLog'], (res) => {
                        renderUserThreatsTable(res.visitLog || []);
                        resolve();
                    });
                });
            });
        });
    }

    // LISTENER: Tab Click (Specific for Reports to auto-load)
    const reportsTabLink = document.querySelector('[data-tab="tab-reports"]');
    if (reportsTabLink) {
        reportsTabLink.addEventListener('click', () => {
            loadUserReports();
        });
    }

    // Initial Load if starting on reports tab (unlikely but good practice)
    if (document.querySelector('#tab-reports.active')) {
        loadUserReports();
    }
});

// --- HELPER FUNCTIONS ---

function loadUserReports() {
    chrome.storage.local.get(['currentUser'], (data) => {
        const user = data.currentUser;

        // Better Feedback for Guest/Logged Out State
        if (!user || !user.email) {
            console.warn("[Dashboard] loadUserReports: No currentUser found.");
            const tbody = document.getElementById('user-reports-body');
            if (tbody) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="4" style="text-align:center; padding:30px; color:#64748b;">
                            <div style="font-size:16px; margin-bottom:10px;">👤 <strong>Guest Mode Active</strong></div>
                            <div>Please <a href="login.html" style="color:#2563eb;">Log In</a> to save and track your reports.</div>
                        </td>
                    </tr>
                `;
            }
            return;
        }

        // --- SYNC CHECK: Verify Background Script Sees Us ---
        chrome.runtime.sendMessage({ type: "GET_DEBUG_IDENTITY" }, (response) => {
            // If response is missing or mismatch
            if (chrome.runtime.lastError || !response || !response.currentUser || response.currentUser.email !== user.email) {
                console.warn("[Dashboard] Extension Sync Mismatch! Background script needs reload.");
                const alertArea = document.getElementById('user-reports-alert');
                if (!alertArea) {
                    const container = document.querySelector('#view-reports .card-body') || document.getElementById('user-reports-body').parentElement.parentElement;
                    if (container) {
                        const div = document.createElement('div');
                        div.id = 'user-reports-alert';
                        div.style.cssText = "background:#fff3cd; color:#856404; padding:15px; margin-bottom:20px; border-radius:8px; border:1px solid #ffeeba; text-align:center; font-size:14px;";
                        div.innerHTML = `
                            <div style="font-weight:bold; font-size:15px; margin-bottom:5px;">⚠️ Extension Update Required</div>
                            <div>The extension needs a quick refresh to recognize your login session for reports.</div>
                            <button id="reload-ext-btn" style="margin-top:10px; cursor:pointer; background:#856404; color:white; border:none; padding:8px 16px; border-radius:6px; font-weight:600;">Fix Now (Reload Extension)</button>
                        `;
                        container.insertBefore(div, container.firstChild);

                        document.getElementById('reload-ext-btn').onclick = () => {
                            chrome.runtime.reload();
                        };
                    }
                }
            }
        });

        // Fetch reports for this user from global server
        console.log(`[Dashboard] Loading reports for: ${user.email} from ${API_BASE}/reports`);
        fetch(`${API_BASE}/reports?reporter=${encodeURIComponent(user.email)}`)
            .then(res => res.json())
            .then(reports => {
                renderUserReportsTable(reports);
            })
            .catch(err => {
                console.error("Failed to fetch reports:", err);
                const tbody = document.getElementById('user-reports-body');
                if (tbody) tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color: #ef4444; padding:20px;">Failed to load reports. Server may be offline.</td></tr>';
            });
    });
}

function renderUserReportsTable(reports) {
    const tbody = document.getElementById('user-reports-body');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (!reports || reports.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:20px; color: #64748b;">You haven\'t reported any sites yet.</td></tr>';
        return;
    }

    // Sort newest first
    reports.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));

    reports.forEach(r => {
        const tr = document.createElement('tr');

        let statusBadge = '<span class="badge" style="background:#ffc107; color:#000; padding:4px 8px; border-radius:4px; font-size:11px; font-weight:bold;">PENDING</span>';
        if (r.status === 'banned') statusBadge = '<span class="badge" style="background:#dc3545; color:#fff; padding:4px 8px; border-radius:4px; font-size:11px; font-weight:bold;">🚫 BANNED</span>';
        else if (r.status === 'ignored') statusBadge = '<span class="badge" style="background:#6c757d; color:#fff; padding:4px 8px; border-radius:4px; font-size:11px; font-weight:bold;">IGNORED</span>';

        let analysisHtml; // Declare analysisHtml here

        if (r.aiAnalysis && r.published) {
            const score = r.aiAnalysis.riskScore || r.aiAnalysis.score || 0;
            const suggestion = r.aiAnalysis.suggestion || 'N/A';
            const reason = r.aiAnalysis.reason || '';

            let color = '#64748b';
            if (suggestion === 'BAN') color = '#dc3545';
            else if (suggestion === 'CAUTION') color = '#d97706';
            else if (suggestion === 'SAFE') color = '#166534';

            // Truncate long reasons
            const shortReason = reason ? (reason.length > 80 ? reason.substring(0, 80) + '...' : reason) : 'Analyzing risk factors...';

            analysisHtml = `
                <div style="font-size:12px;">
                    <div style="margin-bottom:4px;"><strong>Verification:</strong> <span style="color:${color}; font-weight:bold;">${suggestion}</span> (${score}/100)</div>
                    <div style="color:#475569; font-style:italic; line-height:1.4;">"${shortReason}"</div>
                    <div class="view-analysis-btn" style="color:${color}; cursor:pointer; font-size:11px; margin-top:4px; text-decoration:underline; font-weight:600;">View Details</div>
                </div>
             `;
        } else if (r.aiAnalysis && !r.published) {
            // Case where AI has run but Admin hasn't uploaded it yet
            analysisHtml = `
                <div style="font-size:12px;">
                    <div style="margin-bottom:4px; color:#d97706;"><strong>Verification:</strong> <span style="font-style:italic;">Pending Admin Sync</span></div>
                    <div style="color:#94a3b8; font-style:italic;">Analysis completed, waiting for admin approval...</div>
                    <div style="color:#94a3b8; font-size:11px; margin-top:4px;">View Details (Locked)</div>
                </div>
            `;
        } else {
            // Case where AI hasn't run yet
            analysisHtml = `
                <div style="font-size:12px;">
                    <div style="margin-bottom:4px; color:#64748b;"><strong>Verification:</strong> <span style="font-style:italic;">Pending AI Review</span></div>
                    <div style="color:#94a3b8; font-style:italic;">Waiting for system analysis...</div>
                    <div style="color:#94a3b8; font-size:11px; margin-top:4px;">View Details (Locked)</div>
                </div>
            `;
        }

        tr.innerHTML = `
            <td>${new Date(r.timestamp).toLocaleDateString()}</td>
            <td style="max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${r.url}">
                <a href="${r.url}" target="_blank" style="color:#2563eb; text-decoration:none;">${r.hostname || r.url}</a>
            </td>
            <td>${statusBadge}</td>
            <td>${analysisHtml}</td>
        `;

        // Attach Listener Programmatically (CSP Safe)
        const viewBtn = tr.querySelector('.view-analysis-btn');
        if (viewBtn && r.aiAnalysis) {
            viewBtn.addEventListener('click', () => {
                showAnalysisModal(r.aiAnalysis);
            });
        }

        tbody.appendChild(tr);
    });
}

// --- NEW: Custom Modal for Analysis (Rich Design) ---
function showAnalysisModal(analysisData) {
    let modal = document.getElementById('analysis-modal');

    // Determine Risk Theme
    const score = analysisData.score || 0;
    const suggestion = analysisData.suggestion || 'UNKNOWN';

    let themeColor = '#10b981'; // Green (Safe)
    let bgLight = '#ecfdf5';
    let icon = '🛡️';

    if (suggestion === 'BAN' || score > 70) {
        themeColor = '#ef4444'; // Red
        bgLight = '#fef2f2';
        icon = '🚫';
    } else if (suggestion === 'CAUTION' || score > 30) {
        themeColor = '#f59e0b'; // Amber
        bgLight = '#fffbeb';
        icon = '⚠️';
    }

    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'analysis-modal';
        modal.className = 'modal-overlay';
        // Base structure
        modal.innerHTML = `
            <div class="modal-content" style="max-width: 600px; text-align: left; padding:0; border:none;  overflow:hidden; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);">
                <div id="analysis-header" style="padding: 24px; background: ${bgLight}; border-bottom: 2px solid ${themeColor};">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                         <div>
                            <h3 id="analysis-title" style="margin:0; color:${themeColor}; font-size: 22px; display:flex; align-items:center; gap:10px;">
                                ${icon} Analysis Report
                            </h3>
                            <p style="margin:5px 0 0 0; color:#64748b; font-size:12px; font-weight:600;">POWERED BY AI THREAT INTELLIGENCE</p>
                         </div>
                         <div style="text-align:right;">
                            <div style="font-size:32px; font-weight:800; color:${themeColor}; line-height:1;">${score}</div>
                            <div style="font-size:11px; font-weight:700; color:${themeColor}; opacity:0.8;">RISK SCORE</div>
                         </div>
                    </div>
                </div>
                
                <div style="padding: 24px;">
                    <div id="analysis-body" style="background:white; border-radius:0; line-height:1.7; color:#334155; font-size:15px; max-height:400px; overflow-y:auto;"></div>
                    
                    <button id="close-analysis-btn" class="btn-modal btn-primary" style="margin-top:20px; background:${themeColor}; border:none; padding:14px; font-size:14px; letter-spacing:0.5px;">ACKNOWLEDGE & CLOSE</button>
                </div>
            </div>
        `;
        document.body.appendChild(modal);

        // CSP-Safe Listener for Close Button
        const closeBtn = document.getElementById('close-analysis-btn');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => {
                const m = document.getElementById('analysis-modal');
                if (m) {
                    m.classList.remove('active');
                    setTimeout(() => m.style.display = 'none', 300);
                }
            });
        }
    } else {
        // Update Dynamic Colors for Existing Modal
        const header = document.getElementById('analysis-header');
        const title = document.getElementById('analysis-title');
        const closeBtn = document.getElementById('close-analysis-btn');

        if (header) {
            header.style.background = bgLight;
            header.style.borderBottomColor = themeColor;
            header.innerHTML = `
                <div style="display:flex; justify-content:space-between; align-items:center;">
                     <div>
                        <h3 style="margin:0; color:${themeColor}; font-size: 22px; display:flex; align-items:center; gap:10px;">
                            ${icon} Analysis Report
                        </h3>
                        <p style="margin:5px 0 0 0; color:#64748b; font-size:12px; font-weight:600;">POWERED BY AI THREAT INTELLIGENCE</p>
                     </div>
                     <div style="text-align:right;">
                        <div style="font-size:32px; font-weight:800; color:${themeColor}; line-height:1;">${score}</div>
                        <div style="font-size:11px; font-weight:700; color:${themeColor}; opacity:0.8;">RISK SCORE</div>
                     </div>
                </div>
            `;
        }

        if (closeBtn) {
            closeBtn.textContent = "ACKNOWLEDGE & CLOSE";
            closeBtn.style.background = themeColor;
        }
    }

    // Format Body Text
    let content = analysisData.reason || "No detail provided.";

    // Convert markers to HTML for richness
    content = content
        .replace(/🚨/g, '<br><br><span style="background:#fee2e2; color:#b91c1c; padding:2px 6px; border-radius:4px; font-weight:bold;">🚨 THREAT</span>')
        .replace(/•/g, '<br>•')
        .replace(/Page Context:/g, '<br><br><strong style="color:#0f172a;">📄 Page Context:</strong>')
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>'); // Simple Markdown Bold Support

    document.getElementById('analysis-body').innerHTML = content;

    modal.style.display = 'flex';
    requestAnimationFrame(() => modal.classList.add('active'));
}

function initDashboardAuth() {
    if (typeof Auth === 'undefined') {
        setTimeout(initDashboardAuth, 100);
        return;
    }

    const ui = document.getElementById('user-info');
    const un = document.getElementById('user-name');
    const guestNav = document.getElementById('guest-nav');

    Auth.checkSession((user) => {
        if (user) {
            // Logged In
            if (ui) ui.style.display = 'flex';
            if (un) un.textContent = user.name;
            if (guestNav) guestNav.style.display = 'none';
        } else {
            // Guest / Logged Out
            if (ui) ui.style.display = 'none';
            if (guestNav) guestNav.style.display = 'flex';
        }
    });

    const logoutLink = document.getElementById('logout-link');
    if (logoutLink) {
        logoutLink.addEventListener('click', (e) => {
            e.preventDefault();
            if (confirm("Logout?")) {
                Auth.logout(() => { window.location.reload(); });
            }
        });
    }
}

function initProfileModal() {
    const editLink = document.getElementById('edit-profile-link');
    const avatar = document.getElementById('user-avatar');
    const modal = document.getElementById('profile-modal');
    const cancelBtn = document.getElementById('cancel-profile');
    const saveBtn = document.getElementById('save-profile');
    const nameInput = document.getElementById('edit-name');
    const passInput = document.getElementById('edit-password');

    if (!modal) return;

    function openModal() {
        Auth.checkSession((user) => {
            if (user) {
                if (nameInput) nameInput.value = user.name || '';
                if (passInput) passInput.value = '';

                modal.style.display = 'flex';
                // Trigger animation
                requestAnimationFrame(() => {
                    modal.classList.add('active');
                });
            }
        });
    }
    const closeModal = () => {
        modal.classList.remove('active');
        setTimeout(() => {
            modal.style.display = 'none';
        }, 300);
    };

    if (editLink) editLink.addEventListener('click', (e) => { e.preventDefault(); openModal(); });
    if (avatar) {
        avatar.style.cursor = 'pointer';
        avatar.addEventListener('click', openModal);
    }
    if (cancelBtn) cancelBtn.addEventListener('click', closeModal);

    if (saveBtn) {
        saveBtn.addEventListener('click', () => {
            const newName = nameInput.value.trim();
            const newPass = passInput.value;
            if (!newName) { alert("Name required"); return; }

            saveBtn.textContent = 'Saving...';
            saveBtn.disabled = true;

            Auth.checkSession((currentUser) => {
                if (currentUser) {
                    const data = { name: newName };
                    if (newPass) data.password = newPass;

                    Auth.updateProfile(currentUser.email, data, (res) => {
                        saveBtn.textContent = 'Save Changes';
                        saveBtn.disabled = false;
                        if (res.success) {
                            alert("Profile Updated");
                            closeModal();
                            const un = document.getElementById('user-name');
                            if (un) un.textContent = newName;
                        } else {
                            alert(res.message);
                        }
                    });
                }
            });
        });
    }

    const deleteBtn = document.getElementById('delete-profile');
    if (deleteBtn) {
        deleteBtn.addEventListener('click', () => {
            if (confirm("⚠️ WARNING: Are you sure you want to PERMANENTLY delete your account? This cannot be undone.")) {
                Auth.checkSession((user) => {
                    if (user) {
                        Auth.deleteAccount(user.email, () => {
                            alert("Account deleted.");
                            window.location.reload();
                        });
                    }
                });
            }
        });
    }

    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', () => {
            if (confirm("Are you sure you want to logout?")) {
                Auth.logout(() => { window.location.reload(); });
            }
        });
    }
}

function checkAdminAccess() {
    // Check if we are in admin mode (optional for dashboard, but kept for consistency if copied)
    const lockScreen = document.getElementById('lock-screen');
    if (!lockScreen) return; // Dashboard doesn't have lockscreen usually, so strict return.

    // ... Copy logic if needed, but for Dashboard this is mostly checking Handoff ...
    // Dashboard GENERATES handoff. Admin CONSUMES it.
    // So actually Dashboard doesn't need to check access to itself.
    // Dashboard is public (user facing).
}

function updateStats(log) {
    const total = log.length;

    // Safety Elements
    const elTotal = document.getElementById('total-scanned');
    const elSafe = document.getElementById('total-safe');
    const elThreats = document.getElementById('total-threats');
    const elSummary = document.getElementById('report-summary');
    const elTime = document.getElementById('time-spent');

    // --- WEEKLY FILTER LOGIC (User Request: Reset every Monday 00:00) ---
    const now = new Date();
    const day = now.getDay(); // 0(Sun) ... 6(Sat)
    // Calculate days to subtract to get to last Monday
    // Mon(1) -> 0. Tue(2) -> 1. ... Sun(0) -> 6.
    const diffToMon = day === 0 ? 6 : day - 1;

    const startOfWeek = new Date(now);
    startOfWeek.setDate(now.getDate() - diffToMon);
    startOfWeek.setHours(0, 0, 0, 0);
    const startOfWeekMs = startOfWeek.getTime();

    // Filter log for Weekly Chart Data
    const weeklyLog = log.filter(e => (e.timestamp || 0) >= startOfWeekMs);

    let highRisk = 0;
    let medRisk = 0;
    let safe = 0;

    // Calculate Chart Stats based on WEEKLY data
    weeklyLog.forEach(e => {
        if (e.score >= 50) {
            highRisk++;
        } else if (e.score >= 20) {
            medRisk++;
        } else {
            safe++;
        }
    });

    // Calculate Lifetime Stats for Overview Cards (Optional: keep lifetime or switch all?)
    // User specifically asked for "Pie Graph" to be weekly.
    // For consistency, let's keep the Text Stats as Lifetime (Total Scanned) 
    // but the Pie Chart as Weekly Monitoring.

    // Recalculate lifetime threats for the specific text counter? 
    // Actually, elThreats usually pairs with the chart. 
    // Let's make the "Threats Blocked" card satisfy the "Weekly" context too?
    // The user screenshot shows "Threats Blocked: 1" and Chart "1 Threats". They usually match.
    // I will use WEEKLY stats for the "Threats Blocked" card to match the chart.

    // However, "Total Scanned" (elTotal) usually implies lifetime usage. 
    // I will use `log.length` for Total Scanned, but `weeklyLog` for Threats/Safe breakdown in chart.

    // Update Text Elements
    if (elTotal) elTotal.innerText = total; // Lifetime

    // For Safe/Threats detail cards, let's use Weekly to match chart, or Lifetime?
    // If chart resets to 0, and "Threats Blocked" says 500, it looks broken.
    // I will set THREATS BLOCKED (elThreats) to match the CHART (Weekly).
    if (elThreats) elThreats.innerText = highRisk + medRisk;

    // Safe Streak/Total Safe? "Total Safe" implies lifetime. 
    // Let's filter lifetime Safe count for that specific card if needed, 
    // but typically `safe` var is reused. 
    // Let's calculate lifetime safe for the card:
    const lifetimeSafe = log.filter(e => e.score < 20).length;
    if (elSafe) elSafe.innerText = lifetimeSafe;

    if (elTime) elTime.innerText = Math.round(lifetimeSafe * 0.5) + ' min';

    const safePercentage = total > 0 ? Math.round((lifetimeSafe / total) * 100) : 100;
    if (elSummary) elSummary.innerText = `Safety: ${safePercentage}%`;

    // Format Date Range for Label
    const endOfWeek = new Date(startOfWeek);
    endOfWeek.setDate(startOfWeek.getDate() + 6);

    // Format: "Jan 12 - Jan 18"
    const options = { month: 'short', day: 'numeric' };
    const dateRange = `${startOfWeek.toLocaleDateString('en-US', options)} - ${endOfWeek.toLocaleDateString('en-US', options)}`;

    // Update the Date Range Display Below Chart
    const rangeEl = document.getElementById('chart-date-range');
    if (rangeEl) rangeEl.innerText = dateRange;

    // --- RENDER CHARTS ---
    if (typeof SimpleCharts !== 'undefined') {
        // Doughnut: High, Suspicious, Safe (WEEKLY DATA)
        SimpleCharts.doughnut(
            'threat-pie-canvas',
            [highRisk, medRisk, safe],
            ['#dc3545', '#ffc107', '#0d6efd'],
            ['Phishing', 'Suspicious', 'Safe'],
            highRisk + medRisk, // Center Value
            "Weekly"           // Center Label (General Context, specific dates are below)
        );

        // Line: Last 10 Visit Scores (Recent Activity)
        // Get last 10, reverse to show chronological left-to-right
        const recentScores = [...log]
            .sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0)) // Newest first
            .slice(0, 10)
            .reverse() // Chronological
            .map(e => e.score || 0);

        if (recentScores.length > 0) {
            SimpleCharts.line('activity-line-canvas', recentScores, '#0d6efd');
        }
    }

    // Gamification
    chrome.storage.local.get(['userXP', 'userLevel'], (g) => {
        const xp = g.userXP || 0;
        const level = g.userLevel || 1;

        const elRank = document.getElementById('user-rank');
        const elLevel = document.getElementById('user-level');
        const elXP = document.getElementById('current-xp');
        const bar = document.getElementById('xp-bar');
        const elNext = document.getElementById('next-level-xp');

        if (elLevel) elLevel.innerText = level;
        if (elXP) elXP.innerText = xp;
        if (elRank) elRank.innerText = (level >= 20 ? 'Sentinel' : (level >= 5 ? 'Scout' : 'Novice'));

        // Bar
        const prev = Math.pow(level - 1, 2) * 100;
        const next = Math.pow(level, 2) * 100;

        if (elNext) elNext.innerText = next; // Update the label

        // Update Badge Image
        const elBadge = document.getElementById('rank-badge');
        if (elBadge) {
            if (level >= 20) elBadge.src = 'images/badge_sentinel.png';
            else if (level >= 5) elBadge.src = 'images/badge_scout.png';
            else elBadge.src = 'images/badge_novice.png';
        }

        const p = level === 1 ? (xp / 100) * 100 : ((xp - prev) / (next - prev)) * 100;
        if (bar) bar.style.width = Math.min(p, 100) + '%';

        // --- FEATURE UNLOCK UI UPDATES ---
        const featQR = document.getElementById('feat-qr');
        const featCham = document.getElementById('feat-cham');

        if (featQR) {
            // UNLOCKED FOR DEMO
            if (true || level >= 5) {
                featQR.innerHTML = `<span>✅</span> QR Scanner <span style="font-size:9px;">(ACTIVE)</span>`;
                featQR.style.color = '#10b981'; // Success Green
                featQR.style.fontWeight = '600';
            } else {
                featQR.innerHTML = `<span>🔒</span> QR Scanner <span style="font-size:9px; opacity:0.7;">(Lvl 5)</span>`;
                featQR.style.color = '#94a3b8';
                featQR.style.fontWeight = 'normal';
            }
        }

        if (featCham) {
            // UNLOCKED FOR DEMO
            if (true || level >= 20) {
                featCham.innerHTML = `<span>✅</span> Chameleon <span style="font-size:9px;">(ACTIVE)</span>`;
                featCham.style.color = '#10b981'; // Success Green
                featCham.style.fontWeight = '600';
            } else {
                featCham.innerHTML = `<span>🔒</span> Chameleon <span style="font-size:9px; opacity:0.7;">(Lvl 20)</span>`;
                featCham.style.color = '#94a3b8';
                featCham.style.fontWeight = 'normal';
            }
        }
    });

    // --- NEW: Radar Stats Population ---
    const elRadarCount = document.getElementById('radar-threat-count');
    const elRadarLast = document.getElementById('radar-last-threat');

    // Calculate total threats (high risk + medium risk)
    const threats = highRisk + medRisk;

    // Updates
    if (elRadarCount) elRadarCount.innerText = threats.toLocaleString();

    if (elRadarLast) {
        if (threats > 0) {
            // Find most recent threat
            // log items have {timestamp, core, hostname, etc.}
            const lastThreat = [...log]
                .filter(e => e.score > 20)
                .sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0))[0];

            if (lastThreat) {
                elRadarLast.innerText = lastThreat.hostname || "Unknown";
                elRadarLast.style.color = "#dc3545"; // Red for danger
                elRadarLast.title = `Score: ${lastThreat.score} | Detected: ${new Date(lastThreat.timestamp || Date.now()).toLocaleString()}`;
            } else {
                elRadarLast.innerText = "None";
                elRadarLast.style.color = "#adb5bd";
            }
        } else {
            elRadarLast.innerText = "None";
            elRadarLast.style.color = "#28a745"; // Green/Grey if clean
        }
    }

    // --- NEW: Radar Visualization Logic ---
    const radarContainer = document.getElementById('threat-radar');
    if (radarContainer) {
        // Get the absolute latest entry (regardless of whether it's a threat or not)
        const absoluteLast = [...log].sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0))[0];

        // If the very last site visited was High Risk, show red alert blips
        if (absoluteLast && absoluteLast.score > 20) {
            radarContainer.classList.add('danger-mode');
            if (document.getElementById('radar-status')) {
                document.getElementById('radar-status').innerHTML =
                    '<span style="display:inline-block; width:8px; height:8px; background:#dc3545; border-radius:50%; margin-right:5px; animation: blink 0.5s infinite;"></span> Threat Detected!';
                document.getElementById('radar-status').style.color = '#dc3545';
            }
        } else {
            radarContainer.classList.remove('danger-mode');
            // Revert status to normal
            if (document.getElementById('radar-status')) {
                document.getElementById('radar-status').innerHTML =
                    '<span style="display:inline-block; width:8px; height:8px; background:#28a745; border-radius:50%; margin-right:5px; animation: blink 2s infinite;"></span> Active Monitoring';
                document.getElementById('radar-status').style.color = '#28a745';
            }
        }
    }
}

function renderExtensionTable(log) {
    const tbody = document.getElementById('ext-log-body');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (!log || log.length === 0) {
        tbody.innerHTML = '<tr><td colspan=4 align=center>No activity.</td></tr>';
        return;
    }

    [...log].reverse().slice(0, 50).forEach(e => {
        const tr = document.createElement('tr');
        const badgeClass = e.tier === 'HIGH_RISK' ? 'risk-high' : 'risk-med';

        tr.innerHTML = `
            <td>${e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : '-'}</td>
            <td><strong>${e.name}</strong> <small style="color:#6c757d">(${e.id.substring(0, 8)}...)</small></td>
            <td><span class="risk-badge ${badgeClass}">${e.tier}</span></td>
            <td>${e.installType}</td>
        `;
        tbody.appendChild(tr);
    });
}

/**
 * NEW: Render "Threats Encountered" Table (User Dashboard)
 * - Shows only threats (score > 20)
 * - Filters by Current Week (Starts Monday 00:00)
 * - Updates Date Range Display
 */
function renderUserThreatsTable(fullLog) {
    const tbody = document.getElementById('user-threat-table').querySelector('tbody');
    const countEl = document.getElementById('weekly-threat-count');
    const dateRangeEl = document.getElementById('threat-date-range');

    if (!tbody) return;

    // 1. Calculate DATE RANGE (Monday - Sunday)
    const now = new Date();
    const day = now.getDay(); // 0(Sun) is last day of week for us?
    // Let's assume standard ISO: Monday(1) is start.
    // If today is Sunday(0), diff=6. Mon(1) diff=0.
    const diffToMon = day === 0 ? 6 : day - 1;

    const startOfWeek = new Date(now);
    startOfWeek.setDate(now.getDate() - diffToMon);
    startOfWeek.setHours(0, 0, 0, 0);

    const endOfWeek = new Date(startOfWeek);
    endOfWeek.setDate(startOfWeek.getDate() + 6);
    endOfWeek.setHours(23, 59, 59, 999);

    // Format for Display: "Jan 13 - Jan 19"
    const opts = { month: 'short', day: 'numeric' };
    const rangeText = `${startOfWeek.toLocaleDateString('en-US', opts)} - ${endOfWeek.toLocaleDateString('en-US', opts)}`;
    if (dateRangeEl) dateRangeEl.innerText = rangeText;

    // 2. Filter Threats
    // - Must be within startOfWeek -> endOfWeek
    // - Must be score > 20 (Medium or High Risk)
    // - OR if the user wants "Threats Encountered" to imply blocked attacks, use score > 50?
    // - Let's use > 20 to be safe (Suspicious + Phishing)
    const weeklyThreats = fullLog.filter(e => {
        const ts = e.timestamp || 0;
        return ts >= startOfWeek.getTime() && ts <= endOfWeek.getTime() && e.score > 20;
    });

    // 3. Update Count
    if (countEl) countEl.innerText = weeklyThreats.length;

    // 4. Populate Table
    tbody.innerHTML = '';
    if (weeklyThreats.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: #94a3b8; padding: 30px;">No threats encountered this week. Stay safe!</td></tr>';
        return;
    }

    // Sort newest first
    weeklyThreats.sort((a, b) => b.timestamp - a.timestamp);

    weeklyThreats.forEach(t => {
        const tr = document.createElement('tr');

        let type = 'Suspicious';
        let color = '#ffc107'; // Yellow
        if (t.score > 50) {
            type = 'Phishing / Malware';
            color = '#dc3545'; // Red
        }

        tr.innerHTML = `
            <td>${new Date(t.timestamp).toLocaleString()}</td>
            <td style="color: #dc3545; font-weight: bold;">${t.hostname || 'Unknown'}</td>
            <td><span class="badge" style="background:${color}; color:#fff; padding:4px 8px; border-radius:4px;">${type}</span></td>
            <td>${t.score}/100</td>
        `;
        tbody.appendChild(tr);
    });
}

function renderTable(log) {
    const tbody = document.getElementById('log-body');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (log.length === 0) {
        tbody.innerHTML = '<tr><td colspan=4 align=center>No activity.</td></tr>';
        return;
    }

    // Sort by timestamp (newest first) and show most recent 50
    const visibleLogs = [...log].sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0)).slice(0, 50);

    visibleLogs.forEach((e, i) => {
        const tr = document.createElement('tr');

        let status = 'Safe';
        let badgeClass = 'risk-low';

        if (e.score >= 60) {
            status = 'Critical';
            badgeClass = 'risk-high';
        } else if (e.score >= 20) {
            status = 'Warning';
            badgeClass = 'risk-med';
        }

        let timeStr = '-';
        if (e.timestamp) {
            try {
                timeStr = new Date(e.timestamp).toLocaleTimeString();
            } catch (err) { timeStr = 'Invalid Date'; }
        }

        const rowId = `log-row-${i}`;
        tr.innerHTML = `
            <td>${timeStr}</td>
            <td>${e.hostname || 'Local File / Unknown'}</td>
            <td id="trust-${rowId}" class="trust-cell"><span style="color:#adb5bd; font-size:11px;">...</span></td>
            <td>${e.score}/100</td>
            <td><span class="risk-badge ${badgeClass}">${status}</span></td>
        `;
        tbody.appendChild(tr);
    });

    // Valid Hostnames for Trust Score Fetch
    const validEntries = visibleLogs.map((e, i) => ({
        hostname: e.hostname,
        elementId: `trust-log-row-${i}`
    })).filter(e => e.hostname && e.hostname.includes('.'));

    // Async Fetch Trust Scores
    fetchLogTrustScores(validEntries);
}

async function fetchLogTrustScores(entries) {
    if (typeof ThreatIntel === 'undefined') return;

    for (const entry of entries) {
        try {
            // Check cache or fetch
            // We use the same service but we need to be careful not to spam.
            // For now, sequential is safer for the demo server.
            const data = await ThreatIntel.getTrustScore("http://" + entry.hostname);
            const el = document.getElementById(entry.elementId);

            if (el && data) {
                if (data.score === null || data.votes === 0) {
                    el.innerHTML = `<span style="color:#adb5bd; font-size:11px;">No votes</span>`;
                } else {
                    const voteText = data.votes === 1 ? 'vote' : 'votes';
                    const color = data.score >= 80 ? '#198754' : (data.score <= 40 ? '#dc3545' : '#ffc107');
                    el.innerHTML = `<span style="color:${color}; font-weight:bold; font-size:11px;" title="${data.votes} ${voteText}">${data.score}% (${data.votes})</span>`;
                }
            } else if (el) {
                el.innerHTML = `<span style="color:#adb5bd; font-size:11px;">N/A</span>`;
            }
        } catch (e) {
            // Silent fail
        }
    }
}


// --- EXTENSION SCANNER UI (Enterprise Grade) ---
function renderExtensionTable(extensions) {
    const tbody = document.getElementById('extension-table-body');
    // If table doesn't exist (e.g. old HTML), inject checks or fallback
    if (!tbody) return;

    tbody.innerHTML = '';

    if (!extensions || extensions.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:20px; color:#64748b;">No risky extensions detected. System Clean. ✅</td></tr>';
        return;
    }

    // Sort by Risk (Critical First)
    extensions.sort((a, b) => b.riskScore - a.riskScore);

    extensions.forEach(ext => {
        const tr = document.createElement('tr');

        let riskBadge = '<span class="badge" style="background:#dcfce7; color:#166534">SAFE</span>';
        if (ext.tier === 'CRITICAL') riskBadge = '<span class="badge" style="background:#fee2e2; color:#991b1b">CRITICAL</span>';
        else if (ext.tier === 'HIGH_RISK') riskBadge = '<span class="badge" style="background:#ffedd5; color:#9a3412">HIGH RISK</span>';
        else if (ext.tier === 'CAUTION') riskBadge = '<span class="badge" style="background:#fef9c3; color:#854d0e">CAUTION</span>';

        // Manifest Badge
        const mv = ext.manifestVersion || 2;
        const mvBadge = mv === 2
            ? '<span style="font-size:10px; background:#f1f5f9; color:#64748b; padding:2px 6px; border-radius:4px; margin-left:5px;">MV2 (Legacy)</span>'
            : '<span style="font-size:10px; background:#f0fdf4; color:#15803d; padding:2px 6px; border-radius:4px; margin-left:5px;">MV3 (Modern)</span>';

        const safeName = ext.name.replace(/[^a-zA-Z0-9 ]/g, ''); // Unique ID for collapse
        const rowId = `ext-${ext.id}`;

        let detailsHtml = '';
        if (ext.details && ext.details.length > 0) {
            const visible = ext.details.slice(0, 2);
            const hidden = ext.details.slice(2);

            detailsHtml = visible.map(d => `<div>• ${d}</div>`).join('');

            if (hidden.length > 0) {
                detailsHtml += `
                    <div id="more-${rowId}" style="display:none; margin-top:5px;">
                        ${hidden.map(d => `<div>• ${d}</div>`).join('')}
                    </div>
                    <button class="expand-btn" data-target="more-${rowId}" 
                        style="background:#f1f5f9; border:none; color:#2563eb; font-size:11px; padding:2px 6px; border-radius:4px; cursor:pointer; margin-top:4px; font-weight:600;">
                        +${hidden.length} more
                    </button>
                `;
            }
        } else {
            detailsHtml = '<span style="color:#adb5bd; font-style:italic;">No flags detected</span>';
        }

        tr.innerHTML = `
            <td>
                <div style="font-weight:600; color:#1e293b;">${ext.name}</div>
                <div style="font-size:11px; color:#64748b;">ID: ${ext.id} ${mvBadge}</div>
            </td>
            <td>${riskBadge}</td>
            <td>
                <div style="font-size:12px; color:#475569;">
                    ${detailsHtml}
                </div>
            </td>
        `;

        // Attach Event Listener for Expand Button
        const expandBtn = tr.querySelector('.expand-btn');
        if (expandBtn) {
            expandBtn.addEventListener('click', function (e) {
                e.preventDefault();
                const targetId = this.getAttribute('data-target');
                const targetEl = document.getElementById(targetId);
                if (targetEl) {
                    targetEl.style.display = 'block';
                    this.style.display = 'none';
                }
            });
        }

        // Removed AI Analysis Button Logic

        tbody.appendChild(tr);
    });
}

function analyzeExtension(ext, btn) {
    if (!btn) return;
    const originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '🤖 Scanning...';

    // Call API
    fetch(`${API_BASE}/ai/extensions/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            name: ext.name,
            permissions: ext.permissions,
            installType: ext.installType,
            manifestVersion: ext.manifestVersion
        })
    })
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                // Re-use formatting logic but specialized for extensions
                const analysisData = {
                    score: data.risk_score,
                    suggestion: data.risk_score > 70 ? 'BAN' : (data.risk_score > 30 ? 'CAUTION' : 'SAFE'),
                    reason: `
                    **Manifest Analysis:** ${data.manifest_analysis || 'N/A'}<br><br>
                    **Permission Breakdown:**<br>${(data.permission_breakdown || []).map(p => `• ${p}`).join('<br>')}
                    <br><br>
                    **Verdict:** ${data.summary}
                `
                };
                showAnalysisModal(analysisData);
            } else {
                alert("AI Analysis Failed: " + data.message);
            }
        })
        .catch(e => {
            console.error("Analysis Error:", e);
            alert("Failed to connect to AI server.");
        })
        .finally(() => {
            btn.disabled = false;
            btn.innerHTML = originalText;
        });
}

function generateAndPrintReport() {
    chrome.storage.local.get(['visitLog', 'userXP', 'userLevel', 'currentUser'], (data) => {
        const log = data.visitLog || [];
        const user = data.currentUser || { name: 'User' };

        const html = `
            <div class="print-header">
                <img src="images/image.png" style="width:60px; height:60px;">
                <h1>PhishingShield Security Report</h1>
                <p>Generated: ${new Date().toLocaleString()}</p>
            </div>
            <div class="print-section">
                <h3>👤 User Profile</h3>
                <div class="print-card">
                    <p><strong>Name:</strong> ${user.name}</p>
                    <p><strong>Security Rank:</strong> Level ${data.userLevel || 1} (${(data.userLevel || 1) >= 20 ? 'Sentinel' : 'Novice'})</p>
                </div>
            </div>
            <div class="print-section">
                <h3>🔍 Security Summary</h3>
                <div class="print-card">
                    <p><strong>Total Sites Scanned:</strong> ${log.length}</p>
                    <p><strong>Threats Blocked:</strong> ${log.filter(e => e.score > 20).length}</p>
                </div>
            </div>
            <div class="print-section">
                <h3>📅 Recent Activity</h3>
                <table class="print-table">
                    <thead><tr><th>Time</th><th>Domain</th><th>Status</th></tr></thead>
                    <tbody>
                        ${[...log].sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0)).slice(0, 10).map(e =>
            `<tr><td>${new Date(e.timestamp).toLocaleTimeString()}</td><td>${e.hostname}</td><td>${e.score > 20 ? 'Threat' : 'Safe'}</td></tr>`
        ).join('')}
                    </tbody>
                </table>
            </div>
            <div style="text-align:center; font-size:10px; color:#999; margin-top:50px;">
                Generated by PhishingShield Extension
            </div>
        `;

        const container = document.getElementById('print-report-container');
        if (container) {
            container.innerHTML = html;
            document.body.classList.add('printing-mode');
            window.print();
            document.body.classList.remove('printing-mode');
        }
    });
}

function renderLeaderboard(users) {
    const container = document.getElementById('leaderboard-list');
    if (!container) return;

    if (!users || users.length === 0) {
        container.innerHTML = '<div style="color:#adb5bd; padding:10px;">No other users active.</div>';
        return;
    }

    // Sort by XP Descending
    const sorted = [...users].sort((a, b) => (b.xp || 0) - (a.xp || 0)).slice(0, 5);

    let html = '';
    sorted.forEach((u, i) => {
        const rank = i + 1;
        let medal = '';
        if (rank === 1) medal = '🥇';
        else if (rank === 2) medal = '🥈';
        else if (rank === 3) medal = '🥉';
        else medal = `#${rank}`;

        const name = u.name || 'Anonymous';
        const level = u.level || 1;
        const xp = u.xp || 0;

        let rankName = 'Novice';
        if (level >= 20) rankName = 'Sentinel';
        else if (level >= 5) rankName = 'Scout';

        html += `
            <div class="leaderboard-item" style="display:flex; justify-content:space-between; align-items:center; padding: 10px; border-bottom: 1px solid var(--border-color);">
                <div style="display:flex; align-items:center; gap:10px;">
                    <div style="font-weight:bold; font-size:16px; width:30px; text-align:center;">${medal}</div>
                    <div>
                        <div class="lb-name" style="font-weight:600; color:#343a40; font-size:14px;">${name}</div>
                        <div class="lb-rank" style="font-size:12px; color:#6c757d;">Level ${level} <span style="font-size:10px; color:#adb5bd;">(${rankName})</span></div>
                    </div>
                </div>
                <div style="font-weight:bold; color:#0d6efd; font-size:14px;">${xp} XP</div>
            </div>
        `;
    });

    container.innerHTML = html;
}

// ============================================
// VISUAL DNA TAB - Complete Implementation
// ============================================

/**
 * Brand database (mirrored from chameleon.js for dashboard rendering).
 * Since chameleon.js is a content script, the dashboard page
 * needs its own reference to render the signature database UI.
 */
const VDNA_BRAND_DB = {
    "Tech Giants": {
        google: { color: '#4285f4', domains: ['google.com', 'youtube.com', 'gmail.com'] },
        microsoft: { color: '#f25022', domains: ['microsoft.com', 'live.com', 'outlook.com'] },
        apple: { color: '#000000', domains: ['apple.com', 'icloud.com'] },
        amazon: { color: '#ff9900', domains: ['amazon.com', 'amazon.co.uk', 'amazon.in'] },
        meta: { color: '#1877f2', domains: ['facebook.com', 'instagram.com', 'meta.com'] },
        netflix: { color: '#e50914', domains: ['netflix.com'] }
    },
    "Social Media": {
        twitter: { color: '#1d9bf0', domains: ['twitter.com', 'x.com'] },
        linkedin: { color: '#0a66c2', domains: ['linkedin.com'] },
        instagram: { color: '#e1306c', domains: ['instagram.com'] },
        tiktok: { color: '#000000', domains: ['tiktok.com'] },
        pinterest: { color: '#bd081c', domains: ['pinterest.com'] },
        reddit: { color: '#ff4500', domains: ['reddit.com'] },
        discord: { color: '#5865f2', domains: ['discord.com'] },
        snapchat: { color: '#fffc00', domains: ['snapchat.com'] },
        tumblr: { color: '#36465d', domains: ['tumblr.com'] },
        telegram: { color: '#0088cc', domains: ['telegram.org'] },
        whatsapp: { color: '#25d366', domains: ['whatsapp.com'] },
        skype: { color: '#00aff0', domains: ['skype.com'] }
    },
    "Finance & Banking": {
        paypal: { color: '#003087', domains: ['paypal.com'] },
        chase: { color: '#117aca', domains: ['chase.com'] },
        bofa: { color: '#e31837', domains: ['bankofamerica.com'] },
        wellsfargo: { color: '#d71e28', domains: ['wellsfargo.com'] },
        citi: { color: '#003b70', domains: ['citi.com'] },
        capitalone: { color: '#004977', domains: ['capitalone.com'] },
        amex: { color: '#006fcf', domains: ['americanexpress.com'] },
        usbank: { color: '#0c2074', domains: ['usbank.com'] },
        pnc: { color: '#f47c20', domains: ['pnc.com'] },
        truist: { color: '#2e1a47', domains: ['truist.com'] },
        tdbank: { color: '#008a00', domains: ['td.com', 'tdbank.com'] },
        schwab: { color: '#00a0dd', domains: ['schwab.com'] },
        fidelity: { color: '#125e36', domains: ['fidelity.com'] },
        goldmansachs: { color: '#7399c6', domains: ['goldmansachs.com', 'gs.com'] },
        morganstanley: { color: '#000000', domains: ['morganstanley.com'] },
        robinhood: { color: '#00c805', domains: ['robinhood.com'] }
    },
    "International Banking": {
        hsbc: { color: '#db0011', domains: ['hsbc.com'] },
        barclays: { color: '#00aeef', domains: ['barclays.co.uk'] },
        lloyds: { color: '#006a4d', domains: ['lloydsbank.com'] },
        natwest: { color: '#42145f', domains: ['natwest.com'] },
        santander: { color: '#ec0000', domains: ['santander.co.uk'] },
        rbc: { color: '#0051a5', domains: ['rbc.com', 'rbcroyalbank.com'] },
        scotiabank: { color: '#ec111a', domains: ['scotiabank.com'] },
        bmo: { color: '#0079c1', domains: ['bmo.com'] },
        td_canada: { color: '#008a00', domains: ['td.com'] },
        anz: { color: '#004165', domains: ['anz.com.au'] },
        westpac: { color: '#da1710', domains: ['westpac.com.au'] },
        commbank: { color: '#ffcc00', domains: ['commbank.com.au'] },
        nab: { color: '#bf0d3e', domains: ['nab.com.au'] },
        deutsche: { color: '#0018a8', domains: ['db.com'] },
        ubs: { color: '#000000', domains: ['ubs.com'] },
        credit_suisse: { color: '#000000', domains: ['credit-suisse.com'] },
        ing: { color: '#ff6200', domains: ['ing.com'] },
        rabobank: { color: '#fd6400', domains: ['rabobank.com'] }
    },
    "Crypto & Wallets": {
        coinbase: { color: '#0052ff', domains: ['coinbase.com'] },
        binance: { color: '#f0b90b', domains: ['binance.com'] },
        kraken: { color: '#5841d8', domains: ['kraken.com'] },
        kucoin: { color: '#00a38d', domains: ['kucoin.com'] },
        crypto_com: { color: '#002d74', domains: ['crypto.com'] },
        gemini: { color: '#00dcfa', domains: ['gemini.com'] },
        gate_io: { color: '#bf3936', domains: ['gate.io'] },
        bybit: { color: '#f7a600', domains: ['bybit.com'] },
        okx: { color: '#000000', domains: ['okx.com'] },
        bitfinex: { color: '#13aa4f', domains: ['bitfinex.com'] },
        metamask: { color: '#f6851b', domains: ['metamask.io'] },
        phantom: { color: '#ab9ff2', domains: ['phantom.app'] },
        trustwallet: { color: '#3375bb', domains: ['trustwallet.com'] },
        ledger: { color: '#000000', domains: ['ledger.com'] },
        trezor: { color: '#00854d', domains: ['trezor.io'] },
        blockchain: { color: '#121d33', domains: ['blockchain.com'] },
        exodus: { color: '#5e5ce6', domains: ['exodus.com'] },
        myetherwallet: { color: '#05c0a5', domains: ['myetherwallet.com'] }
    },
    "Payment Processors": {
        stripe: { color: '#635bff', domains: ['stripe.com'] },
        square: { color: '#000000', domains: ['squareup.com'] },
        wise: { color: '#9ce657', domains: ['wise.com'] },
        revolut: { color: '#0075eb', domains: ['revolut.com'] },
        cashapp: { color: '#00d632', domains: ['cash.app'] },
        venmo: { color: '#008cff', domains: ['venmo.com'] },
        westernunion: { color: '#ffda00', domains: ['westernunion.com'] },
        moneygram: { color: '#e2001a', domains: ['moneygram.com'] },
        skrill: { color: '#811e4d', domains: ['skrill.com'] },
        neteller: { color: '#8dc63f', domains: ['neteller.com'] },
        payoneer: { color: '#ff4800', domains: ['payoneer.com'] }
    },
    "E-Commerce": {
        ebay: { color: '#e53238', domains: ['ebay.com'] },
        walmart: { color: '#0071dc', domains: ['walmart.com'] },
        target: { color: '#cc0000', domains: ['target.com'] },
        bestbuy: { color: '#0046be', domains: ['bestbuy.com'] },
        alibaba: { color: '#ff6a00', domains: ['alibaba.com'] },
        aliexpress: { color: '#ff4747', domains: ['aliexpress.com'] },
        rakuten: { color: '#bf0000', domains: ['rakuten.com'] },
        shopify: { color: '#95bf47', domains: ['shopify.com'] },
        etsy: { color: '#f16521', domains: ['etsy.com'] },
        costco: { color: '#0060a9', domains: ['costco.com'] },
        homedepot: { color: '#f96302', domains: ['homedepot.com'] },
        lowes: { color: '#004990', domains: ['lowes.com'] },
        macys: { color: '#e01a2b', domains: ['macys.com'] },
        kohls: { color: '#2e4198', domains: ['kohls.com'] },
        wayfair: { color: '#7f187f', domains: ['wayfair.com'] },
        ikea: { color: '#0051ba', domains: ['ikea.com'] },
        nike: { color: '#000000', domains: ['nike.com'] },
        adidas: { color: '#000000', domains: ['adidas.com'] },
        shein: { color: '#000000', domains: ['shein.com'] },
        temu: { color: '#fb7701', domains: ['temu.com'] }
    },
    "Email & Telecom": {
        yahoo: { color: '#6001d2', domains: ['yahoo.com'] },
        aol: { color: '#333333', domains: ['aol.com'] },
        outlook: { color: '#0078d4', domains: ['outlook.live.com', 'hotmail.com'] },
        att: { color: '#00a8e0', domains: ['att.com'] },
        verizon: { color: '#cd040b', domains: ['verizon.com'] },
        tmobile: { color: '#ea0a8e', domains: ['t-mobile.com'] },
        xfinity: { color: '#613393', domains: ['xfinity.com'] },
        spectrum: { color: '#005ba7', domains: ['spectrum.net'] },
        cox: { color: '#00549f', domains: ['cox.com'] },
        centurylink: { color: '#0047bb', domains: ['centurylink.com'] },
        bt: { color: '#5514b4', domains: ['bt.com'] },
        virginmedia: { color: '#ed0000', domains: ['virginmedia.com'] },
        orange: { color: '#ff7900', domains: ['orange.fr'] },
        vodafone: { color: '#e60000', domains: ['vodafone.com'] },
        telekom: { color: '#e20074', domains: ['telekom.de'] }
    },
    "Logistics": {
        fedex: { color: '#4d148c', domains: ['fedex.com'] },
        ups: { color: '#351c15', domains: ['ups.com'] },
        dhl: { color: '#d40511', domains: ['dhl.com'] },
        usps: { color: '#333366', domains: ['usps.com'] },
        royalmail: { color: '#d71921', domains: ['royalmail.com'] },
        canadapost: { color: '#0061a5', domains: ['canadapost.ca'] },
        auspost: { color: '#dc1928', domains: ['auspost.com.au'] }
    },
    "Productivity": {
        dropbox: { color: '#0061fe', domains: ['dropbox.com'] },
        box: { color: '#0061d5', domains: ['box.com'] },
        adobe: { color: '#fa0f00', domains: ['adobe.com'] },
        docusign: { color: '#2d3a46', domains: ['docusign.com'] },
        zoom: { color: '#2d8cff', domains: ['zoom.us'] },
        slack: { color: '#4a154b', domains: ['slack.com'] },
        salesforce: { color: '#00a1e0', domains: ['salesforce.com'] },
        gitlab: { color: '#fc6d26', domains: ['gitlab.com'] },
        github: { color: '#000000', domains: ['github.com'] },
        atlassian: { color: '#0052cc', domains: ['atlassian.com'] },
        bitbucket: { color: '#0052cc', domains: ['bitbucket.org'] },
        aws: { color: '#232f3e', domains: ['aws.amazon.com'] },
        heroku: { color: '#430098', domains: ['heroku.com'] },
        digitalocean: { color: '#0080ff', domains: ['digitalocean.com'] },
        oracle: { color: '#c74634', domains: ['oracle.com'] },
        ibm: { color: '#006699', domains: ['ibm.com'] },
        cisco: { color: '#1ba0d7', domains: ['cisco.com'] },
        teamviewer: { color: '#004e9c', domains: ['teamviewer.com'] },
        webex: { color: '#00bceb', domains: ['webex.com'] },
        logmein: { color: '#000000', domains: ['logmein.com'] }
    },
    "Entertainment": {
        steam: { color: '#171a21', domains: ['steampowered.com'] },
        roblox: { color: '#000000', domains: ['roblox.com'] },
        twitch: { color: '#9146ff', domains: ['twitch.tv'] },
        epicgames: { color: '#303030', domains: ['epicgames.com'] },
        blizzard: { color: '#009cde', domains: ['battle.net'] },
        playstation: { color: '#003791', domains: ['playstation.com'] },
        xbox: { color: '#107c10', domains: ['xbox.com'] },
        nintendo: { color: '#e60012', domains: ['nintendo.com'] },
        riotgames: { color: '#d13639', domains: ['riotgames.com'] },
        ea: { color: '#ff4747', domains: ['ea.com'] },
        ubisoft: { color: '#000000', domains: ['ubisoft.com'] },
        minecraft: { color: '#464646', domains: ['minecraft.net'] },
        spotify: { color: '#1db954', domains: ['spotify.com'] },
        apple_music: { color: '#fa243c', domains: ['music.apple.com'] },
        disneyplus: { color: '#113ccf', domains: ['disneyplus.com'] },
        hulu: { color: '#1ce783', domains: ['hulu.com'] },
        hbo: { color: '#5400ff', domains: ['max.com'] },
        youtube: { color: '#ff0000', domains: ['youtube.com'] }
    },
    "Travel": {
        airbnb: { color: '#ff5a5f', domains: ['airbnb.com'] },
        booking: { color: '#003580', domains: ['booking.com'] },
        expedia: { color: '#00257a', domains: ['expedia.com'] },
        tripadvisor: { color: '#00af87', domains: ['tripadvisor.com'] },
        uber: { color: '#000000', domains: ['uber.com'] },
        lyft: { color: '#ff00bf', domains: ['lyft.com'] },
        delta: { color: '#003a70', domains: ['delta.com'] },
        united: { color: '#005da4', domains: ['united.com'] },
        americanairlines: { color: '#0078d2', domains: ['aa.com'] },
        southwest: { color: '#304cb2', domains: ['southwest.com'] },
        britishairways: { color: '#075aaa', domains: ['britishairways.com'] },
        lufthansa: { color: '#05164d', domains: ['lufthansa.com'] },
        emirates: { color: '#d71920', domains: ['emirates.com'] },
        ryanair: { color: '#073590', domains: ['ryanair.com'] },
        easyjet: { color: '#ff6600', domains: ['easyjet.com'] },
        agoda: { color: '#363636', domains: ['agoda.com'] },
        hotels_com: { color: '#d32f2f', domains: ['hotels.com'] }
    },
    "Government": {
        irs: { color: '#005ea2', domains: ['irs.gov'] },
        uk_gov: { color: '#000000', domains: ['gov.uk'] },
        usa_gov: { color: '#002868', domains: ['usa.gov'] },
        id_me: { color: '#2c8c45', domains: ['id.me'] },
        who: { color: '#0093d5', domains: ['who.int'] },
        un: { color: '#009edb', domains: ['un.org'] },
        europa: { color: '#004494', domains: ['europa.eu'] },
        nasa: { color: '#0b3d91', domains: ['nasa.gov'] },
        nih: { color: '#333333', domains: ['nih.gov'] },
        cdc: { color: '#005eaa', domains: ['cdc.gov'] }
    },
    "Services": {
        wordpress: { color: '#21759b', domains: ['wordpress.com'] },
        wix: { color: '#000000', domains: ['wix.com'] },
        squarespace: { color: '#000000', domains: ['squarespace.com'] },
        godaddy: { color: '#1bdbdb', domains: ['godaddy.com'] },
        namecheap: { color: '#de3723', domains: ['namecheap.com'] },
        bluehost: { color: '#283593', domains: ['bluehost.com'] },
        hostgator: { color: '#ffc425', domains: ['hostgator.com'] },
        eventbrite: { color: '#f05537', domains: ['eventbrite.com'] },
        meetup: { color: '#ed1c40', domains: ['meetup.com'] },
        patreon: { color: '#f96854', domains: ['patreon.com'] },
        onlyfans: { color: '#00aff0', domains: ['onlyfans.com'] },
        medium: { color: '#000000', domains: ['medium.com'] },
        substack: { color: '#ff6719', domains: ['substack.com'] }
    }
};

/**
 * Initialize the Visual DNA tab — called when dashboard loads
 */
function initVisualDNA() {
    renderVdnaHelix();
    renderVdnaBrandDatabase();
    loadVdnaScans();

    // Refresh button listener
    const refreshBtn = document.getElementById('vdna-refresh-timeline');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => {
            refreshBtn.innerHTML = '<span class="icon rotating">🔄</span> Refreshing...';
            loadVdnaScans();
            setTimeout(() => {
                refreshBtn.innerHTML = '<span class="icon">🔄</span> Refresh';
            }, 1000);
        });
    }

    // Count total signatures (from chameleon's 200+ DB)
    const sigEl = document.getElementById('vdna-signatures-count');
    if (sigEl) {
        // Count all brands across all categories
        let totalBrands = 0;
        for (const cat of Object.values(VDNA_BRAND_DB)) {
            totalBrands += Object.keys(cat).length;
        }
        // The actual chameleon.js has 200+ but our dashboard subset shows key ones
        // Display the real number
        sigEl.textContent = '200+';
    }
}

/**
 * Generate DNA Helix Animation (programmatic SVG-like dots)
 */
function renderVdnaHelix() {
    const container = document.getElementById('vdna-helix');
    if (!container) return;

    const colors = ['#818cf8', '#34d399', '#f472b6', '#60a5fa', '#a78bfa', '#34d399'];
    let html = '<div class="vdna-helix">';

    for (let i = 0; i < 24; i++) {
        const angle = (i / 24) * Math.PI * 4;
        const x = 60 + Math.sin(angle) * 35;
        const y = 5 + (i / 24) * 110;
        const color = colors[i % colors.length];
        const delay = (i * 0.15).toFixed(2);

        html += `<div class="vdna-helix-strand" style="left:${x}px;top:${y}px;background:${color};animation-delay:${delay}s;width:${4 + (i % 3)}px;height:${4 + (i % 3)}px;"></div>`;

        // Mirror strand (double helix)
        const x2 = 60 - Math.sin(angle) * 35;
        html += `<div class="vdna-helix-strand" style="left:${x2}px;top:${y}px;background:${color};opacity:0.5;animation-delay:${(delay * 1 + 0.5).toFixed(2)}s;width:${3 + (i % 2)}px;height:${3 + (i % 2)}px;"></div>`;

        // Connecting bar every 3rd
        if (i % 3 === 0) {
            const barWidth = Math.abs(x - x2);
            const barLeft = Math.min(x, x2);
            html += `<div style="position:absolute;left:${barLeft + 2}px;top:${y + 1}px;width:${barWidth - 4}px;height:2px;background:linear-gradient(90deg,${color},transparent,${colors[(i + 3) % colors.length]});opacity:0.3;border-radius:1px;"></div>`;
        }
    }

    html += '</div>';
    container.innerHTML = html;
}

/**
 * Render the brand signature database with category tabs
 */
function renderVdnaBrandDatabase(filterCat = 'all') {
    const tabsContainer = document.getElementById('vdna-cat-tabs');
    const gridContainer = document.getElementById('vdna-brand-grid');
    const dbCountEl = document.getElementById('vdna-db-count');

    if (!tabsContainer || !gridContainer) return;

    // Render category tabs
    const categories = Object.keys(VDNA_BRAND_DB);
    let tabsHtml = `<div class="vdna-cat-tab ${filterCat === 'all' ? 'active' : ''}" data-cat="all">All</div>`;
    categories.forEach(cat => {
        tabsHtml += `<div class="vdna-cat-tab ${filterCat === cat ? 'active' : ''}" data-cat="${cat}">${cat}</div>`;
    });
    tabsContainer.innerHTML = tabsHtml;

    // Tab click handlers
    tabsContainer.querySelectorAll('.vdna-cat-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            renderVdnaBrandDatabase(tab.getAttribute('data-cat'));
        });
    });

    // Render brand cards
    let gridHtml = '';
    let visibleCount = 0;

    const renderBrands = (catName, brands) => {
        for (const [name, data] of Object.entries(brands)) {
            visibleCount++;
            const initial = name.charAt(0).toUpperCase();
            const domainText = data.domains.join(', ');

            gridHtml += `
                <div class="vdna-brand-card" title="${catName}: ${name}\nDomains: ${domainText}">
                    <div class="vdna-brand-swatch" style="background:${data.color};">${initial}</div>
                    <div class="vdna-brand-info">
                        <div class="vdna-brand-name">${name}</div>
                        <div class="vdna-brand-domains">${domainText}</div>
                    </div>
                </div>
            `;
        }
    };

    if (filterCat === 'all') {
        for (const [catName, brands] of Object.entries(VDNA_BRAND_DB)) {
            renderBrands(catName, brands);
        }
    } else if (VDNA_BRAND_DB[filterCat]) {
        renderBrands(filterCat, VDNA_BRAND_DB[filterCat]);
    }

    gridContainer.innerHTML = gridHtml;

    if (dbCountEl) {
        dbCountEl.textContent = `${visibleCount} ${filterCat === 'all' ? 'Brands' : filterCat}`;
    }
}

/**
 * Load scan history from storage and render the timeline + stats
 */
function loadVdnaScans() {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) return;

    chrome.storage.local.get(['visualDnaScans'], (res) => {
        const scans = res.visualDnaScans || [];
        renderVdnaTimeline(scans);
        updateVdnaStats(scans);
    });
}

/**
 * Update stats counters
 */
function updateVdnaStats(scans) {
    const totalEl = document.getElementById('vdna-total-scans');
    const clonesEl = document.getElementById('vdna-clones-detected');
    const cleanEl = document.getElementById('vdna-clean-pages');

    const total = scans.length;
    const clones = scans.filter(s => s.isClone).length;
    const clean = total - clones;

    if (totalEl) totalEl.textContent = total;
    if (clonesEl) clonesEl.textContent = clones;
    if (cleanEl) cleanEl.textContent = clean;

    // Update status pill if clones were detected
    const pill = document.getElementById('vdna-status-pill');
    if (pill && clones > 0) {
        pill.style.background = 'rgba(239, 68, 68, 0.15)';
        pill.style.borderColor = 'rgba(239, 68, 68, 0.3)';
        pill.style.color = '#f87171';
        pill.querySelector('.vdna-status-dot').style.background = '#f87171';
        pill.querySelector('span:last-child').textContent = `⚠️ ${clones} Clone${clones > 1 ? 's' : ''} Detected — Engine Active`;
    }
}

/**
 * Render the scan timeline
 */
function renderVdnaTimeline(scans) {
    const container = document.getElementById('vdna-timeline');
    if (!container) return;

    if (!scans || scans.length === 0) {
        container.innerHTML = `
            <div style="text-align: center; color: #94a3b8; padding: 40px; font-size: 13px;">
                <div style="font-size: 40px; margin-bottom: 12px;">🧬</div>
                No scan data yet. Browse some websites to see Visual DNA analysis here.
            </div>
        `;
        return;
    }

    // Sort newest first, limit to 50
    const sorted = [...scans].sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0)).slice(0, 50);

    let html = '';
    sorted.forEach(scan => {
        const isClone = scan.isClone;
        const iconClass = isClone ? 'danger' : 'safe';
        const icon = isClone ? '🚨' : '✅';
        const hostname = scan.hostname || 'Unknown';
        const brand = scan.brand ? scan.brand.charAt(0).toUpperCase() + scan.brand.slice(1) : null;
        const confidence = scan.confidence || 0;
        const reasons = scan.reasons || [];
        const timeStr = formatTimeAgo(scan.timestamp);

        let subtitle = '';
        if (isClone) {
            subtitle = `Impersonating <strong>${brand}</strong> (${confidence}% match)`;
            if (reasons.length > 0) {
                subtitle += ` — ${reasons.join(', ')}`;
            }
        } else {
            subtitle = 'No brand impersonation detected';
        }

        const badge = isClone
            ? `<span class="vdna-tl-badge clone">🦎 CLONE DETECTED</span>`
            : `<span class="vdna-tl-badge clean">CLEAN</span>`;

        html += `
            <div class="vdna-timeline-item">
                <div class="vdna-tl-icon ${iconClass}">${icon}</div>
                <div class="vdna-tl-body">
                    <div class="vdna-tl-title">${hostname}</div>
                    <div class="vdna-tl-sub">${subtitle}</div>
                    ${badge}
                </div>
                <div class="vdna-tl-time">${timeStr}</div>
            </div>
        `;
    });

    container.innerHTML = html;
}

/**
 * Utility: Format timestamp to "X ago" string
 */
function formatTimeAgo(timestamp) {
    if (!timestamp) return 'Unknown';
    const now = Date.now();
    const diff = now - timestamp;

    const seconds = Math.floor(diff / 1000);
    if (seconds < 60) return 'Just now';

    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ago`;

    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;

    const days = Math.floor(hours / 24);
    if (days < 7) return `${days}d ago`;

    return new Date(timestamp).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

// Initialize Visual DNA when DOM is ready (extend existing DOMContentLoaded)
document.addEventListener('DOMContentLoaded', () => {
    // Defer VDNA init slightly to not block primary dashboard render
    setTimeout(() => {
        initVisualDNA();
    }, 200);

    // Auto-load scans when switching to Visual DNA tab
    const vdnaTabLink = document.querySelector('[data-tab="tab-visual-dna"]');
    if (vdnaTabLink) {
        vdnaTabLink.addEventListener('click', () => {
            loadVdnaScans();
        });
    }
});
