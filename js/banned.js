// banned.js - Handles banned page functionality
// This file is loaded externally to comply with CSP (Content Security Policy)

if (typeof window.DEV_MODE === 'undefined') {
    window.DEV_MODE = true;
}
if (typeof window.API_BASE === 'undefined') {
    window.API_BASE = window.DEV_MODE ? "http://localhost:3000/api" : "https://phishingshield-ruby.vercel.app/api";
}

var DEV_MODE = window.DEV_MODE;
var API_BASE = window.API_BASE;

(function () {
    'use strict';

    console.log('[PhishingShield] banned.js loaded');

    // Initialize when DOM is ready
    function init() {
        // Get URL from query parameter
        const urlParams = new URLSearchParams(window.location.search);
        const blockedUrl = urlParams.get('url') || 'Unknown URL';

        // Display the blocked URL
        const blockedUrlElement = document.getElementById('blocked-url');
        if (blockedUrlElement) {
            blockedUrlElement.textContent = blockedUrl;
            console.log('[PhishingShield] Blocked URL displayed:', blockedUrl);
        }

        // Check if site is still banned (allows auto-redirect on unban)
        checkIfStillBanned(blockedUrl);

        // Setup all button event listeners
        setupEventListeners(blockedUrl);
    }

    // Check if the site is still banned
    async function checkIfStillBanned(url) {
        if (!url || url === 'Unknown URL') return;

        try {
            console.log('[PhishingShield] Checking if site is still banned:', url);

            // Query local server for current ban status
            const response = await fetch(`${API_BASE}/reports`);
            if (!response.ok) {
                console.warn('[PhishingShield] Could not check ban status (server offline?)');
                return;
            }

            const reports = await response.json();

            // Normalize URL for comparison
            let normalizedUrl = url.toLowerCase();
            try {
                const urlObj = new URL(url);
                normalizedUrl = urlObj.hostname.replace(/^www\./, '');
            } catch (e) {
                // Use as-is if parsing fails
            }

            // Check if any report for this URL is still banned
            const isBanned = reports.some(report => {
                if (report.status !== 'banned') return false;

                try {
                    const reportUrl = new URL(report.url);
                    const reportHostname = reportUrl.hostname.replace(/^www\./, '').toLowerCase();
                    return reportHostname === normalizedUrl || report.url.toLowerCase().includes(normalizedUrl);
                } catch (e) {
                    return report.url.toLowerCase().includes(normalizedUrl);
                }
            });

            if (!isBanned) {
                console.log('[PhishingShield] ✅ Site has been unbanned! Redirecting...');

                // Show notification
                const container = document.querySelector('.container');
                if (container) {
                    const notice = document.createElement('div');
                    notice.style.cssText = 'position: fixed; top: 20px; left: 50%; transform: translateX(-50%); background: #10b981; color: white; padding: 15px 30px; border-radius: 8px; font-weight: bold; z-index: 10000; box-shadow: 0 4px 12px rgba(0,0,0,0.2);';
                    notice.textContent = '✅ Site Unbanned! Redirecting...';
                    document.body.appendChild(notice);
                }

                // Redirect after brief delay
                setTimeout(() => {
                    let target = url;
                    if (!target.startsWith('http') && !target.startsWith('file')) {
                        target = 'https://' + target;
                    }
                    window.location.href = target;
                }, 1500);
            } else {
                console.log('[PhishingShield] Site is still banned');
            }
        } catch (error) {
            console.error('[PhishingShield] Error checking ban status:', error);
        }
    }

    function setupEventListeners(blockedUrl) {
        // Go Back button
        const goBackBtn = document.getElementById('go-back-btn');
        if (goBackBtn) {
            goBackBtn.addEventListener('click', function () {
                console.log('[PhishingShield] Go Back clicked');
                // Redirect to dashboard as requested
                window.location.href = chrome.runtime.getURL('dashboard.html');
            });
            console.log('[PhishingShield] ✅ Go Back button handler attached');
        } else {
            console.error('[PhishingShield] ❌ Go Back button not found!');
        }

        // Go Home button
        const goHomeBtn = document.getElementById('go-home-btn');
        if (goHomeBtn) {
            goHomeBtn.addEventListener('click', function () {
                console.log('[PhishingShield] Go Home clicked');
                window.location.href = 'https://www.google.com';
            });
            console.log('[PhishingShield] ✅ Go Home button handler attached');
        } else {
            console.error('[PhishingShield] ❌ Go Home button not found!');
        }

        // Proceed Anyway button
        const proceedBtn = document.getElementById('proceed-anyway-btn');
        if (proceedBtn) {
            // Add hover effects using event listeners (replaces inline onmouseover/onmouseout)
            proceedBtn.addEventListener('mouseenter', function () {
                this.style.background = '#dc3545';
                this.style.color = 'white';
            });

            proceedBtn.addEventListener('mouseleave', function () {
                this.style.background = 'white';
                this.style.color = '#dc3545';
            });

            // Add click handler (replaces inline onclick)
            proceedBtn.addEventListener('click', function () {
                console.log('[PhishingShield] Proceed Anyway button clicked on banned.html');
                console.log('[PhishingShield] Blocked URL:', blockedUrl);

                if (confirm('⚠️ FINAL WARNING\n\nThis site has been banned by PhishingShield administrators.\n\nProceeding may result in:\n• Identity theft\n• Financial loss\n• Malware infection\n• Data breach\n\nAre you absolutely sure you want to continue?')) {
                    console.log('[PhishingShield] User confirmed, attempting navigation...');

                    // APPLY PENALTY HERE (User Requested)
                    console.log('[PhishingShield] Applying 500 XP penalty for proceeding to banned site');

                    // Visual Feedback for User
                    const btn = document.getElementById('proceed-anyway-btn');
                    if (btn) btn.innerText = "Processing penalty...";

                    chrome.runtime.sendMessage({
                        type: 'ADD_XP',
                        amount: -500
                    }, function (response) {
                        if (chrome.runtime.lastError) {
                            console.error("Penalty Message Failed:", chrome.runtime.lastError);
                            alert("Extension Error: Please reload the extension.");
                        } else if (response && response.success) {
                            console.log('[PhishingShield] ✅ 500 XP penalty applied');
                        }
                    });

                    if (blockedUrl && blockedUrl !== 'Unknown URL') {
                        // Normalize URL for consistent matching
                        let normalizedUrl = blockedUrl;
                        try {
                            const urlObj = new URL(blockedUrl);
                            // Store both full URL and hostname for flexible matching
                            normalizedUrl = urlObj.href;
                        } catch (e) {
                            // If URL parsing fails, use as-is
                            normalizedUrl = blockedUrl;
                        }

                        // Store bypass token for one-time use
                        const bypassToken = {
                            url: normalizedUrl,
                            timestamp: Date.now(),
                            used: false
                        };

                        // Store in chrome.storage.local (if available) or sessionStorage
                        if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
                            // Ensure protocol exists for the token to be valid in background.js
                            if (!normalizedUrl.startsWith('http') && !normalizedUrl.startsWith('file')) {
                                normalizedUrl = 'https://' + normalizedUrl;
                            }

                            // Update UI to show processing
                            const proceedBtn = document.getElementById('proceed-anyway-btn');
                            if (proceedBtn) {
                                proceedBtn.textContent = 'Unlocking... 🔓';
                                proceedBtn.disabled = true;
                                proceedBtn.style.opacity = '0.7';
                            }

                            chrome.storage.local.get(['bypassTokens'], function (data) {
                                const tokens = data.bypassTokens || [];
                                // Remove any existing token for this URL (prevent duplicates)
                                const filteredTokens = tokens.filter(t => t.url !== normalizedUrl);
                                filteredTokens.push(bypassToken);
                                chrome.storage.local.set({ bypassTokens: filteredTokens }, function () {
                                    console.log('[PhishingShield] Bypass token stored for one-time use:', normalizedUrl);
                                    // Notify background script to update blocklist (exclude this URL)
                                    chrome.runtime.sendMessage({
                                        type: "UPDATE_BLOCKLIST",
                                        bypassUrl: normalizedUrl
                                    }, function (response) {
                                        // Wait for blocklist to be updated before navigating
                                        if (response && response.success) {
                                            console.log('[PhishingShield] Blocklist updated, navigating to:', blockedUrl);
                                            // Increase delay to 1000ms to ensure Chrome applies the rule change
                                            setTimeout(function () {
                                                // Ensure URL has protocol to avoid relative path (file not found) errors
                                                let target = blockedUrl;
                                                if (!target.startsWith('http') && !target.startsWith('file')) {
                                                    target = 'https://' + target;
                                                }
                                                window.location.href = target;
                                            }, 1000);
                                        } else {
                                            // Fallback: try navigation anyway
                                            console.warn('[PhishingShield] Blocklist update response unclear, attempting navigation');
                                            setTimeout(function () {
                                                let target = blockedUrl;
                                                if (!target.startsWith('http') && !target.startsWith('file')) {
                                                    target = 'https://' + target;
                                                }
                                                window.location.href = target;
                                            }, 1000);
                                        }
                                    });
                                });
                            });
                        } else {
                            // Fallback to sessionStorage
                            const tokens = JSON.parse(sessionStorage.getItem('bypassTokens') || '[]');
                            const filteredTokens = tokens.filter(t => t.url !== normalizedUrl);
                            filteredTokens.push(bypassToken);
                            sessionStorage.setItem('bypassTokens', JSON.stringify(filteredTokens));
                            console.log('[PhishingShield] Bypass token stored (sessionStorage)');
                            window.location.href = blockedUrl;
                        }
                    } else {
                        console.error('[PhishingShield] Cannot proceed - URL is:', blockedUrl);
                        alert('Cannot proceed - URL not available');
                    }
                } else {
                    console.log('[PhishingShield] User cancelled navigation');
                }
            });
            console.log('[PhishingShield] ✅ Proceed Anyway button handler attached');
        } else {
            console.error('[PhishingShield] ❌ Proceed Anyway button not found!');
        }

        // Log the block event
        console.log('[PhishingShield] Community-banned site blocked:', blockedUrl);
    }

    // Run when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        // DOM already loaded
        init();
    }
})();
