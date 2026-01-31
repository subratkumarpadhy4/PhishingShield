// Admin Login Script - External file to comply with CSP
(function () {
    'use strict';

    const API_BASE = "https://oculus-eight.vercel.app/api";
    let currentSessionId = null;

    function showAlert(message, type = 'info') {
        const container = document.getElementById('alert-container');
        if (container) {
            container.innerHTML = `<div class="alert alert-${type}">${message}</div>`;
            setTimeout(() => {
                container.innerHTML = '';
            }, 5000);
        }
    }

    window.handleStep1 = async function () {
        console.log('[Admin Login] handleStep1 called');

        const emailInput = document.getElementById('email');
        const passwordInput = document.getElementById('password');
        const btn = document.getElementById('btn-step1');

        if (!emailInput || !passwordInput) {
            showAlert('Error: Form fields not found. Please refresh the page.', 'danger');
            return;
        }

        const email = emailInput.value.trim();
        const password = passwordInput.value;

        if (!email || !password) {
            showAlert('Please enter both email and password', 'danger');
            return;
        }

        if (!btn) return;

        btn.disabled = true;
        btn.textContent = 'Logging in...';

        try {
            const response = await fetch(`${API_BASE}/auth/admin/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password })
            });

            const data = await response.json();

            if (data.success && data.token) {
                // DIRECT LOGIN SUCCESS (Single Step)
                chrome.storage.local.set({
                    adminToken: data.token,
                    adminUser: data.user
                }, () => {
                    showAlert('Login successful! Redirecting...', 'success');
                    setTimeout(() => {
                        window.location.href = 'admin.html';
                    }, 1000);
                });
            } else if (data.success && data.requiresMFA) {
                // Fallback if server still requires MFA (should not happen with new server code)
                currentSessionId = data.sessionId;
                document.getElementById('step1').classList.add('completed');
                document.getElementById('step1-form').classList.add('hidden');
                document.getElementById('step2-form').classList.remove('hidden');
            } else {
                showAlert(data.message || 'Login failed', 'danger');
                btn.disabled = false;
                btn.textContent = 'Login';
            }
        } catch (error) {
            console.error('Login error:', error);
            showAlert('Network error. Check server status.', 'danger');
            btn.disabled = false;
            btn.textContent = 'Login';
        }
    };

    window.handleStep2 = async function () {
        const otpInput = document.getElementById('otp');
        const btn = document.getElementById('btn-step2');

        if (!otpInput) {
            showAlert('Error: OTP input not found. Please refresh the page.', 'danger');
            return;
        }

        const otp = otpInput.value.trim();

        if (!otp || otp.length !== 6) {
            showAlert('Please enter the 6-digit code', 'danger');
            return;
        }

        if (!currentSessionId) {
            showAlert('Session expired. Please start over.', 'danger');
            return;
        }

        if (!btn) {
            console.error('Step 2 button not found');
            showAlert('Error: Button not found. Please refresh the page.', 'danger');
            return;
        }

        btn.disabled = true;
        btn.textContent = 'Verifying...';

        try {
            const response = await fetch(`${API_BASE}/auth/admin/verify-mfa`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ sessionId: currentSessionId, otp })
            });

            const data = await response.json();

            if (data.success) {
                // Store admin token
                if (typeof chrome !== 'undefined' && chrome.storage) {
                    chrome.storage.local.set({
                        adminToken: data.token,
                        adminUser: data.user
                    }, () => {
                        showAlert('Login successful! Redirecting...', 'success');
                        setTimeout(() => {
                            const adminUrl = chrome.runtime?.getURL ? chrome.runtime.getURL('admin.html') : 'admin.html';
                            window.location.href = adminUrl;
                        }, 1000);
                    });
                } else {
                    // Fallback for non-extension context
                    localStorage.setItem('adminToken', data.token);
                    localStorage.setItem('adminUser', JSON.stringify(data.user));
                    showAlert('Login successful! Redirecting...', 'success');
                    setTimeout(() => {
                        window.location.href = 'admin.html';
                    }, 1000);
                }
            } else {
                showAlert(data.message || 'Invalid verification code', 'danger');
                if (btn) {
                    btn.disabled = false;
                    btn.textContent = 'Verify & Login';
                }
            }
        } catch (error) {
            console.error('MFA error:', error);
            showAlert('Verification failed. Please try again.', 'danger');
            if (btn) {
                btn.disabled = false;
                btn.textContent = 'Verify & Login';
            }
        }
    };

    window.resendOTP = async function () {
        const emailInput = document.getElementById('email');
        if (!emailInput) {
            showAlert('Please enter your email first', 'danger');
            return;
        }

        const email = emailInput.value.trim();
        if (!email) {
            showAlert('Please enter your email first', 'danger');
            return;
        }

        // Trigger step 1 again
        await window.handleStep1();
    };

    // Set up event listeners (required due to CSP blocking inline handlers)
    let listenersAttached = false;
    function initEventListeners() {
        if (listenersAttached) return;
        listenersAttached = true;

        // Step 1 button - PRIMARY handler
        const btnStep1 = document.getElementById('btn-step1');
        if (btnStep1) {
            btnStep1.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                console.log('[Admin Login] Step 1 button clicked');
                window.handleStep1();
            });
            console.log('[Admin Login] Step 1 button listener attached');
        } else {
            console.error('[Admin Login] Step 1 button not found!');
        }

        // Step 2 button
        const btnStep2 = document.getElementById('btn-step2');
        if (btnStep2) {
            btnStep2.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                console.log('[Admin Login] Step 2 button clicked');
                window.handleStep2();
            });
        }

        // Resend OTP button
        const btnResend = document.getElementById('btn-resend-otp');
        if (btnResend) {
            btnResend.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                console.log('[Admin Login] Resend OTP button clicked');
                window.resendOTP();
            });
        }

        // Password Enter key
        const passwordInput = document.getElementById('password');
        if (passwordInput) {
            passwordInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    window.handleStep1();
                }
            });
        }

        // OTP Enter key
        const otpInput = document.getElementById('otp');
        if (otpInput) {
            otpInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    window.handleStep2();
                }
            });

            otpInput.addEventListener('input', (e) => {
                e.target.value = e.target.value.replace(/\D/g, '').substring(0, 6);
            });
        }
    }

    // Initialize immediately and also on DOM ready
    console.log('[Admin Login] Script loaded');
    console.log('[Admin Login] Document ready state:', document.readyState);

    // Try immediately
    initEventListeners();

    // Also try on DOMContentLoaded as backup
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            console.log('[Admin Login] DOMContentLoaded fired, re-initializing listeners');
            initEventListeners();
        });
    }

    // Also try on window load as final backup
    window.addEventListener('load', () => {
        console.log('[Admin Login] Window load fired, re-initializing listeners');
        initEventListeners();
    });
})();

