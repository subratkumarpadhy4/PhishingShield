// REPORTS FILTER STATE
let allReportsCache = [];
let currentReportFilter = 'all';

document.addEventListener('DOMContentLoaded', () => {
    // 0. SECURITY HANDSHAKE
    checkAdminAccess();



    // 1. Sidebar Navigation Logic
    const navLinks = document.querySelectorAll('.nav-link');
    const tabs = document.querySelectorAll('.tab-content');
    const pageTitle = document.getElementById('page-title');

    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();

            // Remove active classes
            navLinks.forEach(l => l.classList.remove('active'));
            tabs.forEach(t => t.classList.remove('active'));

            // Activate content
            link.classList.add('active');
            const tabId = link.getAttribute('data-tab');
            document.getElementById(tabId).classList.add('active');

            // Update Title
            pageTitle.textContent = link.textContent.replace(/^.\s/, ''); // Remove emoji

            // Special Tab Logic
            if (tabId === 'banned-sites') {
                loadBannedSites();
            }
        });
    });

    // Handle "View All" button
    document.getElementById('view-all-users').addEventListener('click', () => {
        document.querySelector('[data-tab="users"]').click();
    });

    // 2. Set Date
    const now = new Date();
    document.getElementById('current-date').textContent = now.toLocaleDateString('en-US', {
        weekday: 'long', year: 'numeric', month: 'long', day: 'numeric'
    });

    // 3. Load Data from Storage
    loadDashboardData();

    // 4. Debug / Simulation Tools
    setupDebugTools();

    // 5. Setup Modal Handlers (Replaces inline onclicks)
    setupModalHandlers();

    // 6. Setup Report Filter Handlers (Safely attached)
    setupReportFilters();

    // 7. Keep-Alive Service (Robust)
    connectKeepAlive();
});

let keepAlivePort;
function connectKeepAlive() {
    if (!chrome.runtime || !chrome.runtime.connect) return;
    try {
        keepAlivePort = chrome.runtime.connect({ name: 'keepAlive' });
        keepAlivePort.onDisconnect.addListener(() => {
            // Reconnect logic
            setTimeout(connectKeepAlive, 5000);
        });
    } catch (e) {
        console.warn('Keep-Alive failed', e);
    }
}

function setupReportFilters() {
    // 1. Filter Tabs
    const filters = ['all', 'pending', 'banned', 'ignored'];
    filters.forEach(status => {
        const btn = document.getElementById(`filter-${status}`);
        if (btn) {
            // Remove any existing inline onclick to be safe (though JS override usually wins)
            btn.onclick = null;
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                setReportFilter(status);
            });
        }
    });

    // 2. Refresh Button (Reports)
    const refreshReportsBtn = document.getElementById('btn-refresh-reports');
    if (refreshReportsBtn) {
        refreshReportsBtn.onclick = null; // Clear existing
        refreshReportsBtn.addEventListener('click', (e) => {
            e.preventDefault();
            const originalText = refreshReportsBtn.innerText;
            refreshReportsBtn.innerText = "Refreshing...";
            refreshReportsBtn.disabled = true;

            // Clear cache to force fresh fetch
            allReportsCache = [];
            chrome.storage.local.set({ cachedGlobalReports: [] }, () => {
                console.log('[Admin] Cache cleared, reloading reports...');
                loadDashboardData(); // This is async but we don't have a promise wrapper here usually

                // Revert UI after a delay (simulating async completion for UI feedback)
                setTimeout(() => {
                    refreshReportsBtn.innerText = originalText;
                    refreshReportsBtn.disabled = false;
                }, 2000);
            });
        });
    }

    // 3. Refresh Button (Banned Sites)
    const refreshBannedBtn = document.getElementById('btn-refresh-banned');
    if (refreshBannedBtn) {
        refreshBannedBtn.onclick = null;
        refreshBannedBtn.addEventListener('click', (e) => {
            e.preventDefault();
            // Assuming loadBannedSites() is global or available
            if (typeof loadBannedSites === 'function') {
                loadBannedSites();
            } else {
                console.warn('[Admin] loadBannedSites is not defined');
            }
        });
    }
}

function setupModalHandlers() {
    // User Modal
    const userModal = document.getElementById('user-modal');
    const userCloseX = document.getElementById('modal-close-x');
    const userCloseBtn = document.getElementById('modal-close-btn');

    if (userCloseX) {
        userCloseX.addEventListener('click', () => {
            if (userModal) userModal.classList.add('hidden');
        });
    }

    if (userCloseBtn) {
        userCloseBtn.addEventListener('click', () => {
            if (userModal) userModal.classList.add('hidden');
        });
    }

    // Report Detail Modal
    const reportModal = document.getElementById('report-modal');
    const reportCloseX = document.getElementById('report-modal-close-x');

    if (reportCloseX) {
        reportCloseX.addEventListener('click', () => {
            if (reportModal) reportModal.classList.add('hidden');
        });
    }
}

function setupDebugTools() {
    // Check Environment
    if (!chrome.runtime || !chrome.runtime.id) {
        const header = document.querySelector('header');
        const alert = document.createElement('div');
        alert.style.cssText = "background:#dc3545; color:white; padding:15px; margin-bottom:20px; border-radius:8px; font-weight:bold; display:flex; align-items:center; gap:10px;";
        alert.innerHTML = "<span>⚠️ RUNNING IN FILE MODE. STORAGE IS DISCONNECTED. PLEASE OPEN VIA EXTENSION POPUP.</span>";
        header.prepend(alert);
    }

    // Add Debug Button
    const container = document.querySelector('#settings .table-container');
    if (container) {
        // Divider
        container.appendChild(document.createElement('hr'));

        // "Memory" Restore Button (No downloads)
        const btnRestore = document.createElement('button');
        btnRestore.className = "btn btn-outline";
        btnRestore.textContent = "🔄 Restore Data to Server";
        btnRestore.title = "Restores missing reports from this browser's memory to the server.";
        btnRestore.onclick = restoreFromMemory;
        container.appendChild(btnRestore);
    }

}

function restoreFromMemory() {
    chrome.storage.local.get(['cachedGlobalReports'], (data) => {
        const cached = data.cachedGlobalReports || [];

        if (cached.length === 0) {
            alert("No saved data found in this browser's memory.");
            return;
        }

        // 1. Fetch Current Server State first to differentiate between "Full Wipe" and "Partial Missing"
        const statusDiv = document.createElement('div');
        statusDiv.style.cssText = "position:fixed; top:20px; right:20px; background:#0d6efd; color:white; padding:15px; border-radius:5px; z-index:10000; font-weight:bold;";
        statusDiv.innerText = "🔍 Checking Server State...";
        document.body.appendChild(statusDiv);

        fetch('http://localhost:3000/api/reports')
            .then(res => res.json())
            .then(serverReports => {
                // map existing IDs for fast lookup
                const serverIds = new Set(serverReports.map(r => r.id));

                // 2. Identify Missing Reports
                const missingReports = cached.filter(r => !serverIds.has(r.id));

                if (missingReports.length === 0) {
                    statusDiv.style.background = "#198754";
                    statusDiv.innerText = "✅ Server is already up-to-date.";
                    setTimeout(() => statusDiv.remove(), 2500);
                    return;
                }

                // 3. User Confirmation based on scenario
                statusDiv.remove(); // Remove checking status
                let message = "";
                if (serverReports.length === 0) {
                    message = `🚨 SERVER WIPE DETECTED!\n\nThe server is empty, but your browser remembers ${missingReports.length} reports.\n\nRestore all data?`;
                } else {
                    message = `⚠️ Sync Gap Detected\n\nFound ${missingReports.length} reports in your memory that are missing from the server.\n\nRestore them now?`;
                }

                if (!confirm(message)) return;

                // 4. Restore Logic
                statusDiv.innerText = "⏳ Syncing...";
                document.body.appendChild(statusDiv);
                statusDiv.style.background = "#0d6efd";

                let count = 0;
                let errors = 0;

                const uploadNext = (index) => {
                    if (index >= missingReports.length) {
                        statusDiv.style.background = "#198754";
                        statusDiv.innerText = `✅ Restoration Complete! (${count} sent)`;
                        setTimeout(() => statusDiv.remove(), 2500);
                        loadDashboardData();
                        return;
                    }

                    const report = missingReports[index];
                    fetch('http://localhost:3000/api/reports', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(report)
                    })
                        .then(res => {
                            if (res.ok) count++;
                            else errors++;
                        })
                        .catch(() => errors++)
                        .finally(() => {
                            statusDiv.innerText = `⏳ Restoring ${count}/${missingReports.length}...`;
                            uploadNext(index + 1);
                        });
                };

                uploadNext(0);
            })
            .catch(err => {
                statusDiv.style.background = "#dc3545";
                statusDiv.innerText = "❌ Connection Failed. Data saved in memory.";
                console.error(err);
                setTimeout(() => statusDiv.remove(), 3000);
            });
    });
}

async function checkAdminAccess() {
    const lockScreen = document.getElementById('lock-screen');
    const lockStatus = document.getElementById('lock-status');
    const API_BASE = "http://localhost:3000/api";

    if (!lockScreen) return;

    // Check for admin token in storage
    chrome.storage.local.get(['adminToken', 'adminTokenExpiry'], async (res) => {
        const token = res.adminToken;
        const expiry = res.adminTokenExpiry;

        // Check if token exists and hasn't expired
        if (!token || !expiry || Date.now() > expiry) {
            // No valid token - redirect to admin login
            if (lockStatus) {
                const redirectToLogin = () => {
                    const adminLoginUrl = chrome.runtime?.getURL ? chrome.runtime.getURL('admin-login.html') : 'admin-login.html';
                    window.location.href = adminLoginUrl;
                };

                lockStatus.innerHTML = `
                    <div style="color:#dc3545; font-size:48px; margin-bottom:10px;">🔒</div>
                    <h3>Admin Access Required</h3>
                    <p>Please login to access the Admin Portal.</p>
                    <p style="color:#6c757d; font-size:14px; margin-top:10px;">Redirecting to login...</p>
                    <button id="manual-redirect-btn" style="margin-top:20px; padding:12px 24px; border:none; background:#0d6efd; color:white; border-radius:6px; cursor:pointer; font-weight:600; display:none;">Go to Admin Login</button>
                `;

                // Show manual button after 2 seconds if redirect didn't work
                setTimeout(() => {
                    const manualBtn = document.getElementById('manual-redirect-btn');
                    if (manualBtn) {
                        manualBtn.style.display = 'block';
                        manualBtn.onclick = redirectToLogin;
                    }
                }, 2000);

                // Auto-redirect after 1 second
                setTimeout(redirectToLogin, 1000);
            }
            return;
        }

        // Verify token with server
        try {
            const response = await fetch(`${API_BASE}/auth/admin/verify`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            const data = await response.json();

            if (data.success) {
                // Authorized Admin
                console.log("[Admin Check] ACCESS GRANTED ✅");
                unlockUI();

                // Trigger Fresh Data Load
                if (typeof Auth !== 'undefined' && Auth.getUsers) {
                    // Background refresh of global data
                    Auth.getUsers(() => {
                        console.log("Admin: Global Data Refreshed");
                        loadDashboardData();
                    });
                    if (Auth.getGlobalReports) Auth.getGlobalReports(() => null);
                }
            } else {
                // Token invalid - clear and redirect
                chrome.storage.local.remove(['adminToken', 'adminTokenExpiry', 'adminUser'], () => {
                    if (lockStatus) {
                        const redirectToLogin = () => {
                            const adminLoginUrl = chrome.runtime?.getURL ? chrome.runtime.getURL('admin-login.html') : 'admin-login.html';
                            window.location.href = adminLoginUrl;
                        };

                        lockStatus.innerHTML = `
                            <div style="color:#dc3545; font-size:48px; margin-bottom:10px;">🔒</div>
                            <h3>Session Expired</h3>
                            <p>Your admin session has expired. Please login again.</p>
                            <p style="color:#6c757d; font-size:14px; margin-top:10px;">Redirecting to login...</p>
                            <button id="manual-redirect-btn-expired" style="margin-top:20px; padding:12px 24px; border:none; background:#0d6efd; color:white; border-radius:6px; cursor:pointer; font-weight:600; display:none;">Go to Admin Login</button>
                        `;

                        // Show manual button after 2 seconds if redirect didn't work
                        setTimeout(() => {
                            const manualBtn = document.getElementById('manual-redirect-btn-expired');
                            if (manualBtn) {
                                manualBtn.style.display = 'block';
                                manualBtn.onclick = redirectToLogin;
                            }
                        }, 2000);

                        // Auto-redirect after 1 second
                        setTimeout(redirectToLogin, 1000);
                    }
                });
            }
        } catch (error) {
            console.error("[Admin Check] Server verification failed:", error);
            // Network error - show error but allow access if token exists (graceful degradation)
            if (lockStatus) {
                const retryBtn = document.createElement('button');
                retryBtn.textContent = 'Retry';
                retryBtn.style.cssText = 'margin-top:20px; padding:12px 24px; border:none; background:#0d6efd; color:white; border-radius:6px; cursor:pointer; font-weight:600;';
                retryBtn.onclick = () => window.location.reload();

                const loginBtn = document.createElement('button');
                loginBtn.textContent = 'Go to Login';
                loginBtn.style.cssText = 'margin-top:10px; padding:10px 20px; border:1px solid #6c757d; background:transparent; color:#6c757d; border-radius:6px; cursor:pointer;';
                loginBtn.onclick = () => {
                    const adminLoginUrl = chrome.runtime?.getURL ? chrome.runtime.getURL('admin-login.html') : 'admin-login.html';
                    window.location.href = adminLoginUrl;
                };

                lockStatus.innerHTML = `
                    <div style="color:#ffc107; font-size:48px; margin-bottom:10px;">⚠️</div>
                    <h3>Server Connection Error</h3>
                    <p>Could not verify admin session. Please check your connection.</p>
                `;
                lockStatus.appendChild(retryBtn);
                lockStatus.appendChild(loginBtn);
            }
        }
    });
}

function unlockUI() {
    const lockScreen = document.getElementById('lock-screen');
    if (lockScreen) {
        lockScreen.style.opacity = '0';
        setTimeout(() => {
            lockScreen.style.display = 'none';
        }, 500);
    }
}

function lockUI() {
    // Default state of HTML, but ensuring it here
    const lockScreen = document.getElementById('lock-screen');
    if (lockScreen) {
        lockScreen.style.display = 'flex';
        lockScreen.style.opacity = '1';
    }
}


// 2. DASHBOARD DATA
function loadDashboardData() {
    // Helper to process data after fetching users
    const processData = (users, globalReports) => {
        const storage = (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) ? chrome.storage.local : {
            get: (keys, cb) => {
                const res = {};
                keys.forEach(k => { const item = localStorage.getItem(k); if (item) res[k] = JSON.parse(item); });
                cb(res);
            }
        };

        storage.get(['visitLog', 'currentUser', 'stats_guest_count', 'reportedSites', 'userXP', 'userLevel'], (data) => {
            const logs = data.visitLog || [];
            // Use Global if available, else local
            const reports = (globalReports && globalReports.length > 0) ? globalReports : (data.reportedSites || []);

            // DYNAMIC FIX: Sync Current User Stats from Global Variables
            // This ensures the Admin Panel sees the latest Level/XP even if the 'users' array is stale.
            const currentEmail = data.currentUser ? data.currentUser.email : null;
            if (currentEmail) {
                const userIndex = users.findIndex(u => u.email === currentEmail);
                console.log("Admin Debug: Current Email", currentEmail, "Index", userIndex, "Global XP", data.userXP);
                if (userIndex !== -1) {
                    // Force update display data from live counters
                    users[userIndex].xp = (data.userXP !== undefined) ? data.userXP : users[userIndex].xp;
                    users[userIndex].level = (data.userLevel !== undefined) ? data.userLevel : users[userIndex].level;
                    console.log("Admin Debug: Synced User Data", users[userIndex]);
                }
            }

            // --- Update Stats Cards ---
            // 1. User Stats
            const signedCount = users.length;
            const unsignedCount = data.stats_guest_count || 0; // Reading tracked guest count
            const totalUsers = signedCount + unsignedCount;

            document.getElementById('stats-total-users').textContent = totalUsers;
            document.getElementById('stats-signed').textContent = signedCount;
            document.getElementById('stats-unsigned').textContent = unsignedCount;

            // 2. Total Threats (count high risk in logs)
            const totalThreats = logs.filter(l => l.score > 20).length;
            document.getElementById('stats-threats').textContent = totalThreats;

            // 3. Active Sessions (Recently Active < 5 min)
            // Estimation based on last Critical Interaction or Join time
            const fiveMinAgo = Date.now() - (5 * 60 * 1000);
            const activeUsers = users.filter(u => (u.lastCriticalTime > fiveMinAgo) || (u.joined > fiveMinAgo)).length + (data.currentUser ? 1 : 0);

            // Stats Card 3 (Active Sessions)
            // Finding by DOM context since ID is missing on Value
            const activeCard = document.querySelectorAll('.card')[2];
            if (activeCard) activeCard.querySelector('.card-value').textContent = activeUsers > 0 ? activeUsers : 1;

            // --- Populate Users Table ---

            // --- Populate Logs Table ---
            // GOD MODE: Aggregate logs from ALL users if available
            let aggregatedLogs = [...logs]; // Start with local logs
            users.forEach(u => {
                if (u.history && Array.isArray(u.history)) {
                    // Tag them with user email for context
                    const userLogs = u.history.map(h => ({ ...h, reporter: u.email }));
                    aggregatedLogs = aggregatedLogs.concat(userLogs);
                }
            });

            // Sort by timestamp (newest first)
            aggregatedLogs.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));

            // Pass aggregated logs to renderUsers for Risk Factor calc
            renderUsers(users, aggregatedLogs);

            renderLogs(aggregatedLogs);

            // --- Populate Reports Table ---
            // Fetch from Node.js Backend
            // Fetch from Node.js Backend 
            fetch('https://phishingshield.onrender.com/api/reports')
                .then(res => {
                    if (!res.ok) {
                        throw new Error(`HTTP ${res.status}: ${res.statusText}`);
                    }
                    return res.json();
                })
            fetch('http://localhost:3000/api/reports')
                .then(res => res.json())
                .then(serverReports => {
                    console.log("[Admin] Fetched Global Reports:", serverReports);
                    console.log("[Admin] Number of reports:", Array.isArray(serverReports) ? serverReports.length : 'Not an array');

                    // --- SERVER RESTORATION LOGIC (Persistence Hack) ---
                    // If server returns EMPTY list (because it reset), but we have a Local Cache,
                    // we assume the server wiped and we RESTORE it from our cache.
                    chrome.storage.local.get(['cachedGlobalReports'], (c) => {
                        const cached = c.cachedGlobalReports || [];

                        if (serverReports.length === 0 && cached.length > 0) {
                            console.warn("⚠️ SERVER DATA LOSS DETECTED! Restoring from Admin Cache...");

                            // 1. Show Recovery UI
                            const alertBox = document.createElement('div');
                            alertBox.style.cssText = "position:fixed; top:20px; right:20px; background:#ffc107; color:black; padding:15px; z-index:9999; border-radius:8px; font-weight:bold; box-shadow:0 5px 15px rgba(0,0,0,0.2);";
                            alertBox.innerHTML = `🔄 Server Reset Detected. Restoring ${cached.length} reports...`;
                            document.body.appendChild(alertBox);

                            // 2. Restore to Server (One by one to avoid payload limits, or batch if API supported)
                            // We'll just push them back effectively.
                            let restoredCount = 0;
                            cached.forEach(report => {
                                fetch('http://localhost:3000/api/reports', {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify(report)
                                }).then(() => {
                                    restoredCount++;
                                    if (restoredCount === cached.length) {
                                        alertBox.style.background = "#198754";
                                        alertBox.style.color = "white";
                                        alertBox.innerHTML = `✅ Server Restored (${restoredCount} reports).`;
                                        setTimeout(() => alertBox.remove(), 3000);
                                        loadDashboardData(); // Reload to confirm
                                    }
                                });
                            });

                            // Use Cached data for NOW so UI looks instant
                            renderReports(cached);

                        } else if (serverReports.length >= cached.length) {
                            // Normal Case: Server has data. Update our Cache.
                            console.log("[Admin] Updating Local Cache with latest Server Data");
                            chrome.storage.local.set({ cachedGlobalReports: serverReports });

                            // MERGE logic for UI - Server data takes precedence for status
                            const localReports = data.reportedSites || [];
                            const mergedReports = [...serverReports];

                            // Add local reports that don't exist on server, but prioritize server status
                            localReports.forEach(localR => {
                                const serverReport = mergedReports.find(serverR => serverR.id === localR.id);
                                if (!serverReport) {
                                    // Local report not on server, add it
                                    mergedReports.push(localR);
                                } else {
                                    // Report exists on both - server status takes precedence
                                    // Server already has the correct status, so we keep it
                                }
                            });

                            mergedReports.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
                            renderReports(mergedReports);
                        } else {
                            // Edge Case: Server has SOME data but less than cache? 
                            // Usually implies partial wipe or just new reports. We trust Server + Cache merge.
                            const mergedCache = [...cached];
                            serverReports.forEach(r => {
                                if (!mergedCache.find(c => c.id === r.id)) mergedCache.push(r);
                            });
                            chrome.storage.local.set({ cachedGlobalReports: mergedCache });
                            renderReports(mergedCache);
                        }
                    });
                })
                .catch(err => {
                    console.warn("[Admin] Could not fetch global reports (Server Offline?)", err);
                    // Fallback to Cache first, then Local
                    chrome.storage.local.get(['cachedGlobalReports'], (c) => {
                        const cached = c.cachedGlobalReports || [];
                        if (cached.length > 0) {
                            console.log("[Admin] Using Offline Cache");
                            renderReports(cached);
                        } else {
                            renderReports(reports); // Fallback to local user reports
                        }
                    });
                });

        });
    };

    // Trigger Load
    console.log("Fetching Data...");

    // 1. Fetch Users logic with Auto-Restore
    const fetchUsers = () => {
        return fetch('http://localhost:3000/api/users')
            .then(res => res.json())
            .then(serverUsers => {
                console.log("[Admin] Fetched Global Users:", serverUsers.length);

                return new Promise((resolve) => {
                    chrome.storage.local.get(['cachedUsers'], (data) => {
                        const cached = data.cachedUsers || [];

                        // CACHE LOGIC:
                        if (serverUsers.length === 0 && cached.length > 0) {
                            console.warn("⚠️ SERVER USER DATA LOSS DETECTED! Restoring users from Admin Cache...");

                            // Restore UI
                            const alertBox = document.createElement('div');
                            alertBox.style.cssText = "position:fixed; top:20px; left:20px; background:#ffc107; color:black; padding:15px; z-index:9999; border-radius:8px; font-weight:bold; box-shadow:0 5px 15px rgba(0,0,0,0.2);";
                            alertBox.innerText = `🔄 Restoring ${cached.length} missing users to server...`;
                            document.body.appendChild(alertBox);

                            // Restore execution
                            let restored = 0;
                            const promises = cached.map(u => {
                                return fetch('http://localhost:3000/api/users/sync', {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify(u)
                                }).then(() => restored++);
                            });

                            Promise.allSettled(promises).then(() => {
                                alertBox.innerText = `✅ Restored ${restored} users.`;
                                alertBox.style.background = "#198754";
                                alertBox.style.color = "white";
                                setTimeout(() => alertBox.remove(), 3000);
                                resolve(cached); // Use cached for now
                            });

                        } else if (serverUsers.length >= cached.length) {
                            // Normal / Update: Update Cache
                            console.log("[Admin] Updating User Cache");
                            chrome.storage.local.set({ cachedUsers: serverUsers });
                            resolve(serverUsers);
                        } else {
                            // Merge
                            const missing = cached.filter(c => !serverUsers.find(s => s.email === c.email));
                            if (missing.length > 0) {
                                console.log(`[Admin] Restoring ${missing.length} missing users`);
                                missing.forEach(u => {
                                    fetch('http://localhost:3000/api/users/sync', {
                                        method: 'POST',
                                        headers: { 'Content-Type': 'application/json' },
                                        body: JSON.stringify(u)
                                    });
                                });
                            }
                            const merged = [...serverUsers, ...missing];
                            chrome.storage.local.set({ cachedUsers: merged });
                            resolve(merged);
                        }
                    });
                });
            })
            .catch(err => {
                console.warn("[Admin] User Fetch Failed (Offline?):", err);
                return new Promise(resolve => {
                    chrome.storage.local.get(['cachedUsers'], r => resolve(r.cachedUsers || []));
                });
            });
    };

    // Execute
    fetchUsers().then(users => {
        // Continue with processData
        chrome.storage.local.get(['reports'], r => {
            // We use the existing processData flow but pass our smart user list
            processData(users || [], []);
        });
    });
}


// Filter Logic
window.setReportFilter = function (status) {
    currentReportFilter = status;

    // Update Buttons UI
    ['all', 'pending', 'banned', 'ignored'].forEach(s => {
        const btn = document.getElementById(`filter-${s}`);
        if (btn) {
            if (s === status) {
                btn.classList.add('btn-active');
                btn.classList.remove('btn-outline');
            } else {
                btn.classList.remove('btn-active');
                btn.classList.add('btn-outline');
            }
        }
    });

    // Re-render
    renderReports();
};

function renderReports(reports) {
    const tbody = document.querySelector('#reports-table tbody');
    if (!tbody) {
        console.error('[Admin] Reports table body not found!');
        return;
    }
    tbody.innerHTML = '';

    // Update Cache if new data provided
    if (reports) {
        allReportsCache = Array.isArray(reports) ? reports : [];
        console.log('[Admin] renderReports called with', allReportsCache.length, 'reports');
    }

    // Use Cache
    let dataToRender = allReportsCache || [];

    // Filter out invalid reports
    dataToRender = dataToRender.filter(r => r && (r.url || r.hostname));

    // Apply Filter
    if (currentReportFilter !== 'all') {
        dataToRender = dataToRender.filter(r => {
            const status = r.status || 'pending';
            return status === currentReportFilter;
        });
    }

    if (!dataToRender || dataToRender.length === 0) {
        const filterText = currentReportFilter !== 'all' ? currentReportFilter : '';
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding: 20px; color:#6c757d;">No ${filterText} reports found.</td></tr>`;
        console.log('[Admin] No reports to display. Filter:', currentReportFilter, 'Total cached:', allReportsCache.length);
        return;
    }

    console.log('[Admin] Rendering', dataToRender.length, 'reports');

    // Sort by Date (newest first)
    const sorted = [...dataToRender].sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));

    sorted.forEach((r, index) => {
        // Validate report has required fields
        if (!r || (!r.url && !r.hostname)) {
            console.warn('[Admin] Skipping invalid report:', r);
            return; // Skip invalid reports
        }

        const date = r.timestamp ? new Date(r.timestamp).toLocaleDateString() : 'Unknown';
        const status = r.status || 'pending';

        // Escape HTML to prevent XSS
        const escapeHtml = (text) => {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = String(text);
            return div.innerHTML;
        };

        let statusBadge = '<span class="badge" style="background:#ffc107; color:black">PENDING</span>';

        // Safely get URL - try multiple sources
        const reportUrl = r.url || r.hostname || 'Unknown URL';
        const escapedUrl = escapeHtml(reportUrl);
        const escapedId = escapeHtml(r.id || '');

        // Safely get hostname
        let hostname = r.hostname;
        if (!hostname && reportUrl !== 'Unknown URL') {
            try {
                hostname = new URL(reportUrl).hostname;
            } catch (e) {
                hostname = reportUrl; // Fallback to full URL if parsing fails
            }
        }
        const escapedHostname = escapeHtml(hostname || reportUrl);

        // Action buttons based on status
        let actionBtn = '';
        if (status === 'banned') {
            statusBadge = '<span class="badge" style="background:#dc3545; color:white">🚫 BANNED</span>';
        } else if (status === 'ignored') {
            statusBadge = '<span class="badge" style="background:#6c757d; color:white">IGNORED</span>';
        }

        // Unified Action: Always show "View Details" to open Modal
        actionBtn = `
            <button class="btn btn-outline action-open-modal" data-id="${escapedId}" style="padding:4px 8px; font-size:12px;">View Details</button>
        `;

        // Parse reporter to separate Name and Email if possible for better display
        let reporterDisplay = r.reporter || 'Anonymous';
        // If format is "Name (email)", we can bold the name
        if (reporterDisplay.includes('(')) {
            const parts = reporterDisplay.split('(');
            const name = parts[0].trim();
            const email = '(' + parts[1]; // keep the email part
            reporterDisplay = `<strong>${escapeHtml(name)}</strong> <span style="font-size:12px; color:#6c757d;">${escapeHtml(email)}</span>`;
        } else {
            reporterDisplay = escapeHtml(reporterDisplay);
        }

        const tr = document.createElement('tr');
        // Truncate URL if too long for display
        const displayUrl = escapedUrl.length > 50 ? escapedUrl.substring(0, 47) + '...' : escapedUrl;
        tr.innerHTML = `
            <td style="font-family:monospace; color:#0d6efd;" title="${escapedUrl}">${displayUrl}</td>
            <td>${reporterDisplay}</td>
            <td>${date}</td>
            <td>${statusBadge}</td>
            <td>${actionBtn}</td>
        `;
        tbody.appendChild(tr);

        // Attach event listeners to buttons (CSP-safe, no inline handlers)

        // 1. Initial "View Details" Button Handler (Pending Status)
        const initialViewBtn = tr.querySelector('.action-initial-view');
        if (initialViewBtn) {
            initialViewBtn.addEventListener('click', (e) => {
                const container = e.target.closest('.action-wrapper');
                if (container) {
                    // Inject the full set of options
                    container.innerHTML = `
                        <button class="btn action-ban-dynamic" style="background:#dc3545; padding:4px 8px; font-size:11px;" title="Block">🚫 BAN</button>
                        <button class="btn action-ignore-dynamic" style="background:#6c757d; padding:4px 8px; font-size:11px;" title="Ignore">✓ IGNORE</button>
                        <button class="btn action-details-dynamic" style="background:#0d6efd; padding:4px 8px; font-size:11px;" title="Details">🔍 DETAILS</button>
                    `;

                    // Bind newly created buttons using closure variables
                    container.querySelector('.action-ban-dynamic').addEventListener('click', () => window.banSite(r.url, r.id));
                    container.querySelector('.action-ignore-dynamic').addEventListener('click', () => window.ignoreReport(r.url, r.id));
                    container.querySelector('.action-details-dynamic').addEventListener('click', () => window.viewSiteDetails(r.url, r.id));
                }
            });
        }

        // 1. Modal trigger
        const modalBtn = tr.querySelector('.action-open-modal');
        if (modalBtn) {
            modalBtn.addEventListener('click', () => {
                const report = allReportsCache.find(x => x.id === (modalBtn.dataset.id || '')) || r;
                openReportModal(report);
            });
        }

        // 2. Standard Listeners (for Banned/Ignored status where buttons exist immediately)
        const banBtn = tr.querySelector('.action-ban');
        if (banBtn) {
            banBtn.addEventListener('click', () => {
                window.banSite(banBtn.dataset.url, banBtn.dataset.id);
            });
        }

        const unbanBtn = tr.querySelector('.action-unban');
        if (unbanBtn) {
            unbanBtn.addEventListener('click', () => {
                window.unbanSite(unbanBtn.dataset.url, unbanBtn.dataset.id);
            });
        }

        const ignoreBtn = tr.querySelector('.action-ignore');
        if (ignoreBtn) {
            ignoreBtn.addEventListener('click', () => {
                window.ignoreReport(ignoreBtn.dataset.url, ignoreBtn.dataset.id);
            });
        }

        const detailsBtn = tr.querySelector('.action-details');
        if (detailsBtn) {
            detailsBtn.addEventListener('click', () => {
                window.viewSiteDetails(detailsBtn.dataset.url, detailsBtn.dataset.id);
            });
        }
    });
}

// Global function to ban a harmful site
window.banSite = async function (url, reportId) {
    console.log('[Admin] banSite called with:', { url, reportId });

    try {
        let hostname;
        try {
            hostname = new URL(url).hostname;
        } catch (e) {
            hostname = url;
            console.warn('[Admin] Could not parse URL, using as-is:', url);
        }

        if (!confirm(`🚫 BAN HARMFUL SITE\n\nThis will block access to:\n${hostname}\n\nAll users will see a warning when visiting this site.\n\nProceed?`)) {
            console.log('[Admin] User cancelled ban');
            return;
        }

        console.log('[Admin] User confirmed ban, proceeding...');

        // Update status on server first and WAIT for response
        const response = await fetch('http://localhost:3000/api/reports/update', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: reportId, status: 'banned' })
        });

        const resData = await response.json();

        if (!response.ok || !resData.success) {
            throw new Error(resData.message || 'Server returned error');
        }

        console.log('[Admin] Server updated successfully, status set to banned');

        // Update cached global reports to reflect the ban immediately
        chrome.storage.local.get(['cachedGlobalReports'], (cacheData) => {
            const cachedReports = cacheData.cachedGlobalReports || [];
            const reportIndex = cachedReports.findIndex(r => r.id === reportId || r.url === url);
            if (reportIndex !== -1) {
                cachedReports[reportIndex].status = 'banned';
                cachedReports[reportIndex].bannedAt = Date.now();
            } else {
                // Add to cache if not present
                cachedReports.push({
                    id: reportId,
                    url: url,
                    hostname: hostname,
                    status: 'banned',
                    bannedAt: Date.now(),
                    timestamp: Date.now(),
                    reporter: 'Admin'
                });
            }
            chrome.storage.local.set({ cachedGlobalReports: cachedReports });
        });

        // Update local storage for immediate UI feedback
        chrome.storage.local.get(['reportedSites', 'blacklist'], (data) => {
            let reports = data.reportedSites || [];
            let blacklist = data.blacklist || [];

            // 1. Update Report Status in local storage
            const reportIndex = reports.findIndex(r => r.id === reportId || r.url === url);
            if (reportIndex !== -1) {
                reports[reportIndex].status = 'banned';
                reports[reportIndex].bannedAt = Date.now();
            } else {
                // If not in local, add it
                reports.push({
                    id: reportId,
                    url: url,
                    hostname: hostname,
                    status: 'banned',
                    bannedAt: Date.now(),
                    timestamp: Date.now()
                });
            }

            // 2. Add to Blacklist (both URL and hostname for better blocking)
            if (!blacklist.includes(url)) {
                blacklist.push(url);
            }
            if (hostname && !blacklist.includes(hostname)) {
                blacklist.push(hostname);
            }

            // 3. Save to storage
            chrome.storage.local.set({ reportedSites: reports, blacklist: blacklist }, () => {
                console.log('[Admin] Site banned, blacklist updated:', blacklist);

                // Notify Background Script to update rules immediately
                chrome.runtime.sendMessage({ type: "UPDATE_BLOCKLIST" }, (response) => {
                    if (chrome.runtime.lastError) {
                        console.error('[Admin] Error sending UPDATE_BLOCKLIST:', chrome.runtime.lastError);
                    }

                    // Also trigger immediate sync for other instances
                    chrome.runtime.sendMessage({ type: "FORCE_BLOCKLIST_SYNC" }, () => {
                        console.log('[Admin] Force sync triggered');
                    });

                    alert(`✅ Site Banned Successfully!\n\n${hostname} is now blocked globally.\n\nAll users across all devices will see a warning page when visiting this site.`);
                    loadDashboardData(); // Refresh UI
                    loadBannedSites(); // Refresh banned sites table
                });
            });
        });
    } catch (error) {
        console.error('[Admin] Error in banSite:', error);
        alert('Error banning site: ' + error.message + '\n\nPlease try again or check your connection.');
    }
};

// Global function to ignore a report (mark as false positive)
window.ignoreReport = async function (url, reportId) {
    if (!confirm(`Mark this report as FALSE POSITIVE?\n\n${url}\n\nThis will mark the site as safe and ignore the report.`)) return;

    try {
        // Update status on server AND WAIT for it
        const response = await fetch('http://localhost:3000/api/reports/update', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: reportId, status: 'ignored' })
        });
        const resData = await response.json();

        if (!response.ok || !resData.success) {
            throw new Error(resData.message || 'Server returned error');
        }

        console.log("[Admin] Server ignored report successfully.");
    } catch (err) {
        console.error('Server update failed:', err);
        alert("Warning: Could not update server. Updating locally only.");
    }

    // Now update UI
    chrome.storage.local.get(['reportedSites'], (data) => {
        let reports = data.reportedSites || [];
        const reportIndex = reports.findIndex(r => r.id === reportId || r.url === url);
        if (reportIndex !== -1) {
            reports[reportIndex].status = 'ignored';
            reports[reportIndex].ignoredAt = Date.now();
            chrome.storage.local.set({ reportedSites: reports }, () => {
                alert(`✓ Report Ignored\n\nThis site has been marked as safe.`);
                loadDashboardData();
            });
        }
    });
};

// Global function to unban a site
window.unbanSite = async function (url, reportId) {
    console.log('[Admin] unbanSite called with:', { url, reportId });

    try {
        let hostname;
        try {
            hostname = new URL(url).hostname;
        } catch (e) {
            hostname = url;
            console.warn('[Admin] Could not parse URL, using as-is:', url);
        }

        if (!confirm(`Unban this site?\n\n${url}\n\nThis will allow users to visit the site again.`)) {
            console.log('[Admin] User cancelled unban');
            return;
        }

        console.log('[Admin] User confirmed unban, proceeding...');

        // Update status on server and WAIT for response
        const response = await fetch('http://localhost:3000/api/reports/update', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: reportId, status: 'pending' })
        });

        const resData = await response.json();

        if (!response.ok || !resData.success) {
            throw new Error(resData.message || 'Server returned error');
        }

        console.log('[Admin] Server updated successfully, status set to pending');

        // Update cached global reports to reflect the unban immediately
        chrome.storage.local.get(['cachedGlobalReports'], (cacheData) => {
            const cachedReports = cacheData.cachedGlobalReports || [];
            const reportIndex = cachedReports.findIndex(r => r.id === reportId || r.url === url);
            if (reportIndex !== -1) {
                cachedReports[reportIndex].status = 'pending';
                delete cachedReports[reportIndex].bannedAt;
            }
            chrome.storage.local.set({ cachedGlobalReports: cachedReports });
        });

        chrome.storage.local.get(['reportedSites', 'blacklist'], (data) => {
            let reports = data.reportedSites || [];
            let blacklist = data.blacklist || [];

            // Update report status
            const reportIndex = reports.findIndex(r => r.id === reportId || r.url === url);
            if (reportIndex !== -1) {
                reports[reportIndex].status = 'pending';
                delete reports[reportIndex].bannedAt;
            }

            // Remove from blacklist (both URL and hostname)
            blacklist = blacklist.filter(item => item !== url && item !== hostname);

            console.log('[Admin] Site unbanned, blacklist updated:', blacklist);

            chrome.storage.local.set({ reportedSites: reports, blacklist: blacklist }, () => {
                chrome.runtime.sendMessage({ type: "UPDATE_BLOCKLIST" }, (response) => {
                    if (chrome.runtime.lastError) {
                        console.error('[Admin] Error sending UPDATE_BLOCKLIST:', chrome.runtime.lastError);
                    }

                    // Also trigger immediate sync for other instances
                    chrome.runtime.sendMessage({ type: "FORCE_BLOCKLIST_SYNC" }, () => {
                        console.log('[Admin] Force sync triggered');
                    });

                    alert(`✅ Site Unbanned\n\nUsers can now visit this site.`);
                    loadDashboardData(); // Refresh UI
                    loadBannedSites(); // Refresh banned sites table
                });
            });
        });
    } catch (error) {
        console.error('[Admin] Error in unbanSite:', error);
        alert('Error unbanning site: ' + error.message + '\n\nPlease try again or check your connection.');
    }
};

// Global function to view site details
window.viewSiteDetails = function (url, reportId) {
    chrome.storage.local.get(['reportedSites'], (data) => {
        const reports = data.reportedSites || [];
        const report = reports.find(r => r.id === reportId || r.url === url);

        const hostname = new URL(url).hostname;
        const details = `
🚨 SITE REPORT DETAILS

URL: ${url}
Hostname: ${hostname}
Report ID: ${reportId}
Status: ${report?.status || 'pending'}
Reported by: ${report?.reporter || 'Unknown'}
Reported at: ${report?.timestamp ? new Date(report.timestamp).toLocaleString() : 'Unknown'}
${report?.bannedAt ? `Banned at: ${new Date(report.bannedAt).toLocaleString()}` : ''}

Actions:
• Copy URL to clipboard
• Open site in new tab (to verify)
• Export report data
        `;

        const action = confirm(details + '\n\nOpen this site in a new tab to verify?');
        if (action) {
            chrome.tabs.create({ url: url, active: false });
        }
    });
};

function renderUsers(users, allLogs) {
    const recentBody = document.querySelector('#recent-users-table tbody');
    const allBody = document.querySelector('#all-users-table tbody');

    if (!recentBody || !allBody) return;

    recentBody.innerHTML = '';
    allBody.innerHTML = '';

    if (users.length === 0) {
        recentBody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 20px;">No users registered yet.</td></tr>';
        allBody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding: 20px;">No users database found.</td></tr>';
        return;
    }

    // Sort users by joined date (descending)
    // Note: older user objects might not have 'joined', so fallback
    const sortedUsers = [...users].sort((a, b) => (b.joined || 0) - (a.joined || 0));

    sortedUsers.forEach((user, index) => {
        // Prepare Data
        const name = user.name || 'Unknown';
        const email = user.email || 'N/A';
        const level = user.level || 1;
        const xp = user.xp || 0;
        const joinedDate = user.joined ? new Date(user.joined).toLocaleDateString() : 'Unknown';

        // Calc Risk & Activity
        const userLogs = allLogs ? allLogs.filter(l => l.reporter === email) : [];
        const highRisk = userLogs.filter(l => l.score > 50).length;
        let riskBadge = '<span class="badge" style="background:#198754; color:white">LOW</span>';
        if (highRisk > 5) riskBadge = '<span class="badge" style="background:#dc3545; color:white">HIGH</span>';
        else if (highRisk > 0) riskBadge = '<span class="badge" style="background:#ffc107; color:black">MEDIUM</span>';

        let lastActive = 'Never';
        if (user.lastCriticalTime) lastActive = new Date(user.lastCriticalTime).toLocaleString();
        else if (user.joined) lastActive = new Date(user.joined).toLocaleDateString();

        // --- 1. Recent Users Row (Limit 5) ---
        if (index < 5) {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>
                    <div style="display:flex; align-items:center; gap:10px;">
                        <div style="width:32px; height:32px; background:#e9ecef; border-radius:50%; display:flex; align-items:center; justify-content:center; font-weight:bold; color:#6c757d;">
                            ${name.charAt(0).toUpperCase()}
                        </div>
                        ${name}
                    </div>
                </td>
                <td>${email}</td>
                <td><span class=\"badge badge-user\">User</span></td>
                <td><span class=\"badge badge-active\">Active</span></td>
                <td>${joinedDate}</td>
            `;
            recentBody.appendChild(row);
        }

        // --- 2. All Users Row ---
        // Calculate detailed XP progress (mock max 1000 for visuals)
        const xpPercent = Math.min((xp / (level * 100)) * 100, 100);

        const allRow = document.createElement('tr');
        // REPLACED: Added Last Active and Risk Factor columns
        allRow.innerHTML = `
            <td><strong>${name}</strong></td>
            <td>${email}</td>
            <td>Lvl ${level}</td>
            <td style="font-size:12px; color:#6c757d;">${lastActive}</td>
            <td>${riskBadge}</td>
        `;

        // Create Action Cell Programmatically
        const actionCell = document.createElement('td');
        const viewBtn = document.createElement('button');
        viewBtn.className = 'btn btn-outline';
        viewBtn.style.padding = '4px 8px';
        viewBtn.style.fontSize = '12px';
        viewBtn.textContent = 'View Details';

        viewBtn.addEventListener('click', () => {
            // Populate Modal
            document.getElementById('modal-name').textContent = name;
            document.getElementById('modal-email').textContent = email;
            document.getElementById('modal-avatar').textContent = name.charAt(0).toUpperCase();
            document.getElementById('modal-rank').textContent = user.level > 5 ? 'Elite' : 'Novice';

            document.getElementById('modal-xp').textContent = user.xp || 0;
            document.getElementById('modal-level').textContent = user.level || 1;
            document.getElementById('modal-streak').textContent = user.safeStreak || 0;

            const lastIncident = user.lastCriticalTime ? new Date(user.lastCriticalTime).toLocaleDateString() : 'None';
            document.getElementById('modal-incident').textContent = lastIncident;

            // History
            const histBody = document.getElementById('modal-history-body');
            histBody.innerHTML = '';

            if (user.history && user.history.length > 0) {
                [...user.history].reverse().slice(0, 10).forEach(h => {
                    const row = document.createElement('tr');
                    const riskColor = h.score > 50 ? '#dc3545' : '#198754';
                    row.innerHTML = `
                        <td>${h.timestamp ? new Date(h.timestamp).toLocaleTimeString() : 'N/A'}</td>
                        <td style="max-width:200px; overflow:hidden; text-overflow:ellipsis;">${h.url}</td>
                        <td style="color:${riskColor}; font-weight:bold;">${h.score}%</td>
                    `;
                    histBody.appendChild(row);
                });
            } else {
                histBody.innerHTML = '<tr><td colspan="3" style="text-align:center; padding:10px; color:#adb5bd;">No synced history available.</td></tr>';
            }
            document.getElementById('user-modal').classList.remove('hidden');

            // DYNAMIC BUTTON INJECTION into Modal Footer
            const footer = document.getElementById('modal-footer');
            if (footer) {
                footer.innerHTML = ''; // Clear previous

                // 1. Edit XP Button
                const editXPBtn = document.createElement('button');
                editXPBtn.className = 'btn btn-outline';
                editXPBtn.textContent = 'Edit XP';
                editXPBtn.style.color = '#ffc107';
                editXPBtn.style.borderColor = '#ffc107';
                editXPBtn.onclick = () => {
                    const newXPStr = prompt(`Update XP for ${name}\n\nCurrent: ${user.xp}`, user.xp);
                    if (newXPStr === null) return;

                    const newXP = parseInt(newXPStr);
                    if (isNaN(newXP) || newXP < 0) {
                        alert("Invalid XP");
                        return;
                    }

                    // Sync Logic
                    const updatedUser = { ...user, xp: newXP, level: Math.floor(Math.sqrt(newXP / 100)) + 1 };

                    fetch('http://localhost:3000/api/users/sync', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(updatedUser)
                    })
                        .then(res => res.json())
                        .then(data => {
                            if (data.success) {
                                alert("XP Updated & Synced!");
                                // Quick UI update
                                document.getElementById('modal-xp').textContent = newXP;
                                document.getElementById('modal-level').textContent = updatedUser.level;
                                // Background refresh
                                loadDashboardData();
                            } else {
                                alert("Sync failed: " + data.message);
                            }
                        })
                        .catch(e => alert("Server Error"));
                };

                // 2. Delete Button
                const deleteUserBtn = document.createElement('button');
                deleteUserBtn.className = 'btn btn-outline';
                deleteUserBtn.textContent = 'Delete User';
                deleteUserBtn.style.color = '#dc3545';
                deleteUserBtn.style.borderColor = '#dc3545';
                deleteUserBtn.onclick = () => {
                    if (confirm(`Delete ${name}? This cannot be undone.`)) {
                        fetch('http://localhost:3000/api/users/delete', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ email: email })
                        }).then(() => {
                            alert("User deleted.");
                            document.getElementById('user-modal').classList.add('hidden');
                            loadDashboardData();
                        }).catch(e => alert("Delete failed: " + e));
                    }
                };

                // 3. Close Button
                const closeBtn = document.createElement('button');
                closeBtn.className = 'btn btn-outline';
                closeBtn.textContent = 'Close';
                closeBtn.onclick = () => document.getElementById('user-modal').classList.add('hidden');

                // Append with proper spacing
                footer.appendChild(editXPBtn);
                footer.appendChild(deleteUserBtn);
                footer.appendChild(closeBtn);
            }
        });

        actionCell.appendChild(viewBtn);
        // Note: Edit and Delete buttons moved to Modal Footer

        allRow.appendChild(actionCell);

        allBody.appendChild(allRow);
    });
}


function loadBannedSites() {
    const tbody = document.getElementById('banned-table-body');
    if (!tbody) return;

    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;">Loading...</td></tr>';

    // Fetch from server to get global banned sites
    fetch('http://localhost:3000/api/reports')
        .then(res => res.json())
        .then(serverReports => {
            // Filter for banned sites from server (global bans)
            const bannedSites = serverReports.filter(r => r.status === 'banned');

            if (bannedSites.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding: 20px; color:#adb5bd;">No banned sites found.</td></tr>';
                return;
            }

            tbody.innerHTML = '';
            bannedSites.forEach(site => {
                const row = document.createElement('tr');
                const escapedUrl = site.url.replace(/'/g, "\\'").replace(/"/g, '&quot;');
                const escapedId = (site.id || '').replace(/'/g, "\\'").replace(/"/g, '&quot;');
                row.innerHTML = `
                    <td>
                        <div style="font-weight:600;">${site.url}</div>
                        <div style="font-size:12px; color:#adb5bd;">${site.hostname || site.url}</div>
                    </td>
                    <td>${new Date(site.timestamp || site.bannedAt || Date.now()).toLocaleDateString()}</td>
                    <td>${site.reporter || site.reportedBy || 'Unknown'}</td>
                    <td>
                        <button class="btn btn-outline" style="color: #28a745; border-color: #28a745; font-size: 12px; padding: 4px 8px;" onclick="unbanSite('${escapedUrl}', '${escapedId}')">
                            ✅ Unban
                        </button>
                        ${site.notes ? `<div style="font-size:10px; margin-top:5px; color:#6c757d;">Note: ${site.notes}</div>` : ''}
                    </td>
                `;
                tbody.appendChild(row);
            });
        })
        .catch(err => {
            console.error('[Admin] Failed to fetch banned sites from server:', err);
            tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding: 20px; color:#dc3545;">Error loading banned sites. Please refresh.</td></tr>';
        });
}



function renderLogs(logs) {
    const tbody = document.querySelector('#logs-table tbody');
    if (!tbody) return;

    tbody.innerHTML = '';

    if (logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 20px; color:#adb5bd;">No threats detected yet. System clean.</td></tr>';
        return;
    }

    // Show last 20 logs
    const recentLogs = [...logs].reverse().slice(0, 20);

    recentLogs.forEach(log => {
        const time = new Date(log.timestamp).toLocaleString();
        const score = log.score || 0;

        // Determine Badges
        let statusHtml = '';
        if (score > 50) statusHtml = '<span class="badge" style="background:#dc3545; color:white">CRITICAL</span>';
        else if (score > 20) statusHtml = '<span class="badge" style="background:#ffc107; color:black">WARNING</span>';
        else statusHtml = '<span class="badge" style="background:#198754; color:white">SAFE</span>';

        // Reason logic
        const reasons = (log.reasons || []).join(', ').substring(0, 50) + (log.reasons?.length > 1 ? '...' : '');

        const row = document.createElement('tr');
        const reporterDisplay = log.reporter ? `<span title="${log.reporter}" style="cursor:help; border-bottom:1px dotted #ccc;">${log.reporter.split('@')[0]}...</span>` : '<span class="badge badge-user">Local</span>';

        row.innerHTML = `
            <td>${time}</td>
            <td>${reporterDisplay}</td>
            <td style="font-family:monospace; color:#0d6efd; max-width:150px; overflow:hidden; text-overflow:ellipsis;">${log.hostname}</td>
            <td>${reasons || 'N/A'}</td>
            <td>${score}/100</td>
            <td>${statusHtml}</td>
        `;
        tbody.appendChild(row);
    });
}

function openReportModal(report) {
    const modal = document.getElementById('report-modal');
    if (!modal) return;

    // Populate Data
    document.getElementById('report-modal-url').textContent = report.url;
    document.getElementById('report-modal-reporter').textContent = report.reporter || 'Anonymous';
    document.getElementById('report-modal-date').textContent = new Date(report.timestamp).toLocaleString();

    // Status Badge
    const statusContainer = document.getElementById('report-modal-status-container');
    const status = report.status || 'pending';
    if (status === 'banned') statusContainer.innerHTML = '<span class="badge" style="background:#dc3545; color:white">🚫 BANNED</span>';
    else if (status === 'ignored') statusContainer.innerHTML = '<span class="badge" style="background:#6c757d; color:white">IGNORED</span>';
    else statusContainer.innerHTML = '<span class="badge" style="background:#ffc107; color:black">PENDING REVIEW</span>';

    // --- AI ANALYSIS LOGIC ---
    const aiLoading = document.getElementById('ai-loading');
    const aiResult = document.getElementById('ai-result-container');
    const aiAction = document.getElementById('ai-action-container');
    const btnRunAI = document.getElementById('btn-run-ai');

    // Reset UI
    aiLoading.style.display = 'none';
    aiResult.style.display = 'none';
    aiAction.style.display = 'none';

    // ALWAYS show the Action Button first, never auto-show result
    aiAction.style.display = 'block';

    // Logic: If we have data, we just "reveal" it. If not, we fetch it.
    btnRunAI.onclick = () => {
        aiAction.style.display = 'none';

        if (report.aiAnalysis) {
            // Just Reveal Existing Data
            renderAIResult(report.aiAnalysis);
            return;
        }

        // Else, Fetch New Data
        aiLoading.style.display = 'block';
        fetch('http://localhost:3000/api/reports/ai-verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: report.id })
        })
            .then(res => res.json())
            .then(data => {
                aiLoading.style.display = 'none';
                if (data.success && data.aiAnalysis) {
                    report.aiAnalysis = data.aiAnalysis;
                    renderAIResult(report.aiAnalysis);
                } else {
                    alert("AI Analysis Failed: " + (data.error || 'Unknown Error'));
                    aiAction.style.display = 'block'; // Reset
                }
            })
            .catch(err => {
                aiLoading.style.display = 'none';
                aiAction.style.display = 'block';
                alert("Network Error during AI Scan.");
            });
    };

    function renderAIResult(analysis) {
        aiResult.style.display = 'block';
        const score = analysis.phishing_risk_score || analysis.score || 0;
        const suggestion = analysis.suggestion;

        document.getElementById('ai-score').textContent = `Risk Score: ${score}/100`;
        document.getElementById('ai-reason').textContent = analysis.reason || "Analysis completed.";

        const badge = document.getElementById('ai-badge');
        badge.textContent = `AI: ${suggestion}`;

        if (suggestion === 'BAN') {
            badge.style.background = '#fee2e2';
            badge.style.color = '#dc2626';
        } else if (suggestion === 'CAUTION') {
            badge.style.background = '#fef3c7';
            badge.style.color = '#d97706';
        } else {
            badge.style.background = '#dcfce7';
            badge.style.color = '#166534';
        }
    }


    // Footer Actions
    const footer = document.getElementById('report-modal-footer');
    footer.innerHTML = '';

    // Create Buttons dynamically
    // 1. BAN (if not already banned)
    if (status !== 'banned') {
        const banBtn = document.createElement('button');
        banBtn.className = 'btn';
        banBtn.style.background = '#dc3545';
        banBtn.style.color = 'white';
        banBtn.innerHTML = '🚫 Ban Site';
        banBtn.onclick = () => {
            window.banSite(report.url, report.id);
            modal.classList.add('hidden');
        };
        footer.appendChild(banBtn);
    }

    // 2. UNBAN (if banned)
    if (status === 'banned') {
        const unbanBtn = document.createElement('button');
        unbanBtn.className = 'btn';
        unbanBtn.style.background = '#198754';
        unbanBtn.style.color = 'white';
        unbanBtn.textContent = '✅ Unban Site';
        unbanBtn.onclick = () => {
            window.unbanSite(report.url, report.id);
            modal.classList.add('hidden');
        };
        footer.appendChild(unbanBtn);
    }

    // 3. IGNORE (if pending)
    if (status === 'pending') {
        const ignoreBtn = document.createElement('button');
        ignoreBtn.className = 'btn btn-outline';
        ignoreBtn.textContent = '✓ Ignore Report';
        ignoreBtn.onclick = () => {
            window.ignoreReport(report.url, report.id);
            modal.classList.add('hidden');
        };
        footer.appendChild(ignoreBtn);
    }

    // 4. Verify Link
    const verifyBtn = document.createElement('button');
    verifyBtn.className = 'btn btn-outline';
    verifyBtn.style.borderColor = '#0d6efd';
    verifyBtn.style.color = '#0d6efd';
    verifyBtn.innerHTML = '🔗 Open Link';
    verifyBtn.onclick = () => {
        chrome.tabs.create({ url: report.url, active: false });
    };
    footer.appendChild(verifyBtn);

    // 5. Close Button
    const closeBtn = document.createElement('button');
    closeBtn.className = 'btn btn-outline';
    closeBtn.style.marginLeft = '10px';
    closeBtn.textContent = 'Close';
    closeBtn.onclick = () => modal.classList.add('hidden');
    footer.appendChild(closeBtn);

    // Show
    modal.classList.remove('hidden');
}

/* --- COMMUNITY TRUST MANAGER LOGIC --- */
document.addEventListener('DOMContentLoaded', () => {
    // Button Bindings
    const refreshTrustBtn = document.getElementById('btn-refresh-trust');
    if (refreshTrustBtn) {
        refreshTrustBtn.addEventListener('click', loadTrustData);
    }

    const syncTrustBtn = document.getElementById('btn-sync-trust');
    if (syncTrustBtn) {
        syncTrustBtn.addEventListener('click', handleTrustSync);
    }

    const clearTrustBtn = document.getElementById('btn-clear-trust');
    if (clearTrustBtn) {
        clearTrustBtn.addEventListener('click', handleClearTrust);
    }

    // Tab Listener Hook
    const trustTabLink = document.querySelector('[data-tab="trust"]');
    if (trustTabLink) {
        trustTabLink.addEventListener('click', () => {
            loadTrustData();
            checkTrustSyncStatus();
        });
    }
});

function loadTrustData() {
    const tbody = document.querySelector('#trust-table tbody');
    if (!tbody) return;

    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">Fetching data...</td></tr>';

    fetch('http://localhost:3000/api/trust/all')
        .then(res => res.json())
        .then(data => {
            if (!data || data.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding:20px; color:#6c757d;">No trust data recorded yet.</td></tr>';
                return;
            }

            tbody.innerHTML = '';

            // Sort by Total Votes (Impact) descending
            data.sort((a, b) => (b.safe + b.unsafe) - (a.safe + a.unsafe));

            data.forEach(item => {
                const total = item.safe + item.unsafe;
                const score = total === 0 ? 50 : Math.round((item.safe / total) * 100);

                let statusBadge = '';
                if (score >= 70) statusBadge = '<span class="badge" style="background:#dcfce7; color:#166534">SAFE</span>';
                else if (score <= 30) statusBadge = '<span class="badge" style="background:#fee2e2; color:#991b1b">MALICIOUS</span>';
                else statusBadge = '<span class="badge" style="background:#fff7ed; color:#9a3412">SUSPICIOUS</span>';

                // Progress Bar for visual score
                const progressBar = `
                    <div style="width:100px; height:6px; background:#e2e8f0; border-radius:3px; overflow:hidden; display:inline-block; vertical-align:middle; margin-right:8px;">
                        <div style="width:${score}%; height:100%; background:${score >= 70 ? '#10b981' : (score > 30 ? '#f59e0b' : '#ef4444')}"></div>
                    </div>
                    <span style="font-weight:bold; font-size:12px;">${score}%</span>
                `;

                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td style="font-weight:600; color:#1e293b;">${item.domain}</td>
                    <td>${progressBar}</td>
                    <td style="color:#166534;">+${item.safe}</td>
                    <td style="color:#dc3545;">-${item.unsafe}</td>
                    <td>${statusBadge} <span style="font-size:11px; color:#64748b; margin-left:5px;">(${total} votes)</span></td>
                `;
                tbody.appendChild(tr);
            });
        })
        .catch(err => {
            console.error("Failed to load trust data:", err);
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:#dc3545;">Error loading data. Is server running?</td></tr>';
        });
}

function handleTrustSync() {
    const btn = document.getElementById('btn-sync-trust');
    const statusEl = document.getElementById('trust-sync-status');

    if (btn) btn.disabled = true;
    if (statusEl) statusEl.innerText = "Syncing...";

    fetch('http://localhost:3000/api/trust/sync', { method: 'POST' })
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                if (statusEl) {
                    statusEl.innerText = "Synced";
                    statusEl.className = "badge badge-active";
                }
                checkTrustSyncStatus(); // Update timestamp
                alert(`Successfully synced ${data.syncedCount} records to Global Server.`);
            }
        })
        .catch(err => {
            if (statusEl) {
                statusEl.innerText = "Failed";
                statusEl.className = "badge badge-admin";
            }
            alert("Sync failed. Local server may be offline relative to Global.");
        })
        .finally(() => {
            if (btn) btn.disabled = false;
        });
}

function checkTrustSyncStatus() {
    fetch('http://localhost:3000/api/trust/sync-status')
        .then(res => res.json())
        .then(data => {
            const timeEl = document.getElementById('trust-last-sync');
            const statusEl = document.getElementById('trust-sync-status');

            if (data.lastSync) {
                const date = new Date(data.lastSync).toLocaleString();
                if (timeEl) timeEl.innerText = `Last: ${date}`;
                if (statusEl) {
                    statusEl.innerText = "Online";
                    statusEl.className = "badge badge-active";
                }
            } else {
                if (statusEl) statusEl.innerText = "Pending Upload";
            }
        })
        .catch(() => {
            const statusEl = document.getElementById('trust-sync-status');
            if (statusEl) {
                statusEl.innerText = "Offline";
                statusEl.className = "badge";
                statusEl.style.background = "#e2e8f0";
            }
        });
}

function handleClearTrust() {
    if (!confirm("⚠️ Are you sure you want to delete ALL trust scores?\n\nThis cannot be undone.")) return;

    fetch('http://localhost:3000/api/trust/clear', { method: 'POST' })
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                alert("Trust history cleared successfully.");
                loadTrustData(); // Reload table (should be empty)
            }
        })
        .catch(err => {
            console.error(err);
            alert("Failed to clear history.");
        });
}

// --- LOGOUT LOGIC (Moved from inline script) ---
document.addEventListener('DOMContentLoaded', () => {
    const userPanel = document.querySelector('.user-panel');
    if (userPanel && !document.getElementById('admin-logout-btn')) {
        const logoutBtn = document.createElement('button');
        logoutBtn.id = 'admin-logout-btn';
        logoutBtn.textContent = 'Logout';
        logoutBtn.style.cssText = 'margin-top: 10px; width: 100%; padding: 8px; background: #dc3545; color: white; border: none; border-radius: 6px; cursor: pointer; font-weight: 600;';
        logoutBtn.onclick = () => {
            chrome.storage.local.remove(['adminToken', 'adminTokenExpiry', 'adminUser'], () => {
                const adminLoginUrl = chrome.runtime?.getURL ? chrome.runtime.getURL('admin-login.html') : 'admin-login.html';
                window.location.href = adminLoginUrl;
            });
        };
        userPanel.appendChild(logoutBtn);
    }
});
