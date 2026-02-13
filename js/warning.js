const urlParams = new URLSearchParams(window.location.search);
const targetUrl = urlParams.get('url');
const reason = urlParams.get('reason');
const blockedDomain = urlParams.get('domain');

// Check if this is an IP Logger
if (reason === 'iplogger') {
    const container = document.getElementById('warning-container');
    container.innerHTML = `
        <div class="icon" style="font-size: 5rem;">🕵️</div>
        <h1 style="color: #dc3545; font-size: 2rem;">IP Logger Detected & Blocked!</h1>
        <p style="font-size: 1.2rem; font-weight: bold; color: #ff6b6b;">
            This link is an <strong>IP Tracking Trap</strong>. It was designed to steal your IP address and location.
        </p>
        <p style="font-size: 1rem; color: #6c757d; line-height: 1.8;">
            <strong>How it works:</strong> The attacker creates a tracking link on <code style="background:#2a2a3a;padding:2px 6px;border-radius:4px;color:#ff6b6b;">${blockedDomain || 'an IP logger service'}</code>, 
            sends it to you disguised as a normal link, and when you click it — your IP, location, browser, 
            and device info are logged before redirecting you to a legitimate site (like YouTube) so you never suspect anything.
        </p>
        <p style="font-size: 1rem; color: #10b981; font-weight: 600;">
            ✅ Oculus blocked the connection — your IP was NOT exposed.
        </p>
        ${blockedDomain ? `<p style="font-size: 0.9rem; color: #6c757d; font-family: monospace; word-break: break-all; background: #1a1a2e; padding: 10px; border-radius: 8px; border: 1px solid #333;">🚫 Blocked domain: ${blockedDomain}</p>` : ''}
        <div class="actions">
            <button id="go-back" style="background-color: #dc3545; font-size: 1.1rem; padding: 12px 24px;">Go Back to Safety</button>
        </div>
        <p style="margin-top: 20px; font-size: 0.85rem; color: #6c757d;">
            Known IP logger services are permanently blocked by Oculus. No data was sent to the tracking server.
        </p>
    `;

    // Hide the "Proceed Anyway" button — never allow IP loggers
    const proceedBtn = document.getElementById('proceed-unsafe');
    if (proceedBtn) proceedBtn.style.display = 'none';

    document.getElementById('go-back').addEventListener('click', () => {
        history.back();
    });

    // Log the attempt
    chrome.runtime.sendMessage({
        type: "LOG_VISIT",
        data: {
            url: blockedDomain || 'ip-logger',
            hostname: blockedDomain || 'ip-logger',
            score: 999,
            reason: 'IP_LOGGER_BLOCKED',
            timestamp: Date.now()
        }
    });

} else if (reason === 'COMMUNITY_BAN') {
    // Show banned site message
    const container = document.getElementById('warning-container');
    container.innerHTML = `
        <div class="icon" style="font-size: 5rem;">🚫</div>
        <h1 style="color: #dc3545; font-size: 2rem;">This Site is Banned by PhishingShield</h1>
        <p style="font-size: 1.2rem; font-weight: bold; color: #721c24;">
            This website has been reported and banned by the PhishingShield community.
        </p>
        <p style="font-size: 1rem; color: #6c757d;">
            Access to this site has been blocked for your protection.
        </p>
        ${targetUrl ? `<p style="font-size: 0.9rem; color: #6c757d; font-family: monospace; word-break: break-all;">Blocked URL: ${targetUrl}</p>` : ''}
        <div class="actions">
            <button id="go-back" style="background-color: #dc3545; font-size: 1.1rem; padding: 12px 24px;">Go Back to Safety</button>
        </div>
        <p style="margin-top: 30px; font-size: 0.85rem; color: #6c757d;">
            This site was identified as harmful and has been permanently blocked by PhishingShield administrators.
        </p>
    `;

    // Only allow going back, no proceed option for banned sites
    document.getElementById('go-back').addEventListener('click', () => {
        history.back();
    });

    // Log banned site access attempt
    if (targetUrl) {
        try {
            const urlObj = new URL(targetUrl);
            chrome.runtime.sendMessage({
                type: "LOG_VISIT",
                data: {
                    url: targetUrl,
                    hostname: urlObj.hostname,
                    score: 999, // Special code for "Blocked/Banned"
                    reason: 'COMMUNITY_BAN',
                    timestamp: Date.now()
                }
            });
        } catch (e) {
            console.error("Error logging banned site access", e);
        }
    }
} else {
    // Regular phishing warning (existing behavior)
    // Log this as a "Rescued" / "Blocked" event
    if (targetUrl) {
        try {
            const urlObj = new URL(targetUrl);
            chrome.runtime.sendMessage({
                type: "LOG_VISIT",
                data: {
                    url: targetUrl,
                    hostname: urlObj.hostname,
                    score: 999, // Special code for "Blocked/Rescued"
                    timestamp: Date.now()
                }
            });
        } catch (e) {
            console.error("Error logging blocked visit", e);
        }
    }

    document.getElementById('go-back').addEventListener('click', () => {
        history.back();
    });

    const proceedBtn = document.getElementById('proceed-unsafe');
    if (proceedBtn) {
        proceedBtn.addEventListener('click', (e) => {
            e.preventDefault();
            console.log('[PhishingShield] Proceed button clicked');
            console.log('[PhishingShield] Target URL:', targetUrl);

            if (targetUrl) {
                // Show strong warning before proceeding
                const confirmed = confirm(
                    '⚠️ SECURITY WARNING ⚠️\n\n' +
                    'This site has been flagged as potentially dangerous!\n\n' +
                    'Proceeding may expose you to:\n' +
                    '• Phishing attacks\n' +
                    '• Identity theft\n' +
                    '• Malware\n' +
                    '• Financial fraud\n\n' +
                    'Are you absolutely sure you want to continue?'
                );

                if (confirmed) {
                    console.log('[PhishingShield] User confirmed, navigating to:', targetUrl);
                    // Log that user proceeded despite warning
                    try {
                        const urlObj = new URL(targetUrl);
                        chrome.runtime.sendMessage({
                            type: "LOG_VISIT",
                            data: {
                                url: targetUrl,
                                hostname: urlObj.hostname,
                                score: 100, // High risk - user proceeded anyway
                                reason: 'USER_OVERRIDE',
                                timestamp: Date.now()
                            }
                        });
                    } catch (e) {
                        console.error("Error logging override", e);
                    }

                    // Navigate to the URL
                    window.location.href = targetUrl;
                } else {
                    console.log('[PhishingShield] User cancelled navigation');
                }
            } else {
                console.error('[PhishingShield] No target URL available');
                alert('Cannot proceed - URL not available. Please check the browser console for details.');
            }
        });
    } else {
        console.error('[PhishingShield] Proceed button not found!');
    }
}
