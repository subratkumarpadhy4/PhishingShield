/**
 * Scanning Page Logic
 * Receives scan results from background.js and displays them
 */
const params = new URLSearchParams(window.location.search);
const targetUrl = params.get('url');
const score = parseInt(params.get('score') || '0');
const reasons = params.get('reasons') ? JSON.parse(decodeURIComponent(params.get('reasons'))) : [];

// Display URL
document.getElementById('url-display').textContent = targetUrl || 'Unknown URL';

// Animate checks
const checkIds = ['check-tld', 'check-typo', 'check-pattern', 'check-keywords', 'check-structure'];
let delay = 200;

checkIds.forEach((id, i) => {
    setTimeout(() => {
        const el = document.getElementById(id);
        // Determine if this check found an issue
        const isFail = reasons.some(r => {
            if (id === 'check-tld') return r.includes('TLD') || r.includes('domain');
            if (id === 'check-typo') return r.includes('typo') || r.includes('similar');
            if (id === 'check-pattern') return r.includes('pattern') || r.includes('random') || r.includes('hyphen');
            if (id === 'check-keywords') return r.includes('keyword') || r.includes('phishing');
            if (id === 'check-structure') return r.includes('structure') || r.includes('subdomain') || r.includes('length');
            return false;
        });

        el.classList.add(isFail ? 'fail' : 'done');
        el.querySelector('.icon').textContent = isFail ? '❌' : '✅';
    }, delay * (i + 1));
});

// Show results after animation
setTimeout(() => {
    if (score >= 50) {
        // SUSPICIOUS — show warning
        document.getElementById('result-danger').classList.add('show');
        document.getElementById('danger-reasons').innerHTML = reasons.map(r => `• ${r}`).join('<br>');
        document.getElementById('status').textContent = `Risk Score: ${score}/100`;
        document.getElementById('status').style.color = '#ff6b6b';
    } else {
        // SAFE — auto-redirect
        document.getElementById('result-safe').classList.add('show');
        document.getElementById('status').textContent = 'URL is clean!';
        document.getElementById('status').style.color = '#00ff88';

        // Auto-redirect after 1 second
        setTimeout(() => {
            if (targetUrl) {
                // Tell background to whitelist this URL temporarily
                chrome.runtime.sendMessage({
                    type: 'URL_SCAN_BYPASS',
                    url: targetUrl
                }, () => {
                    window.location.href = targetUrl;
                });
            }
        }, 1000);
    }
}, 1400);

// Button handlers
document.getElementById('btn-back').addEventListener('click', () => {
    history.back();
});

document.getElementById('btn-proceed').addEventListener('click', () => {
    if (targetUrl) {
        const confirmed = confirm(
            '⚠️ This URL was flagged as suspicious!\n\n' +
            'Proceeding may expose your data.\n' +
            'Are you sure?'
        );
        if (confirmed) {
            chrome.runtime.sendMessage({
                type: 'URL_SCAN_BYPASS',
                url: targetUrl
            }, () => {
                window.location.href = targetUrl;
            });
        }
    }
});
