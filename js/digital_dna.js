/**
 * Digital DNA - Fingerprint Spoofing Module
 * Injected into the Main World execution environment.
 * Overrides navigator and screen properties to create a "Shadow Profile".
 * 
 * Protection Layers:
 * 1. Navigator Spoofing (User-Agent, Platform, CPU, RAM, Vendor)
 * 2. Screen Resolution Spoofing (1920x1080)
 * 3. Canvas Noise Injection (Anti-Fingerprinting)
 */
(function () {
    // 🛡️ CONFIGURATION: Shadow Profile Data (Windows 10 / Chrome)
    const SHADOW_PROFILE = {
        userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        appVersion: "5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        platform: "Win32",
        vendor: "Google Inc.",
        hardwareConcurrency: 8, // Pretend to have 8 cores
        deviceMemory: 8,        // Pretend to have 8GB RAM
        screenWidth: 1920,
        screenHeight: 1080
    };

    console.log("%c[Digital DNA] 🧬 Shadow Profile Activated", "color: #00ff00; background: #000; font-size: 12px; padding: 4px;");

    // 🛠️ HELPER: Property Override (Robust)
    function overrideProperty(object, property, value) {
        try {
            Object.defineProperty(object, property, {
                get: () => value,
                configurable: true
            });
        } catch (e) {
            try {
                const proto = Object.getPrototypeOf(object);
                Object.defineProperty(proto, property, {
                    get: () => value,
                    configurable: true
                });
            } catch (e2) {
                console.warn(`[Digital DNA] Failed to override ${property}`, e2);
            }
        }
    }

    try {
        // ════════════════════════════════════════════
        // 1. NAVIGATOR SPOOFING
        // ════════════════════════════════════════════
        const nav = window.navigator;

        overrideProperty(nav, 'userAgent', SHADOW_PROFILE.userAgent);
        overrideProperty(nav, 'appVersion', SHADOW_PROFILE.appVersion);
        overrideProperty(nav, 'platform', SHADOW_PROFILE.platform);
        overrideProperty(nav, 'vendor', SHADOW_PROFILE.vendor);
        overrideProperty(nav, 'hardwareConcurrency', SHADOW_PROFILE.hardwareConcurrency);
        overrideProperty(nav, 'deviceMemory', SHADOW_PROFILE.deviceMemory);

        console.log(`[Digital DNA] ✅ Navigator Spoofed → ${navigator.platform} / ${navigator.userAgent.slice(0, 50)}...`);

        // ════════════════════════════════════════════
        // 2. SCREEN RESOLUTION SPOOFING
        // ════════════════════════════════════════════
        const screen = window.screen;
        overrideProperty(screen, 'width', SHADOW_PROFILE.screenWidth);
        overrideProperty(screen, 'height', SHADOW_PROFILE.screenHeight);
        overrideProperty(screen, 'availWidth', SHADOW_PROFILE.screenWidth);
        overrideProperty(screen, 'availHeight', SHADOW_PROFILE.screenHeight - 40); // Minus taskbar

        console.log(`[Digital DNA] ✅ Screen Spoofed → ${screen.width}x${screen.height}`);

        // ════════════════════════════════════════════
        // 3. CANVAS NOISE INJECTION (Anti-Fingerprinting)
        // ════════════════════════════════════════════
        const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
        HTMLCanvasElement.prototype.toDataURL = function (type) {
            try {
                const ctx = this.getContext('2d');
                if (ctx && this.width > 0 && this.height > 0) {
                    const imageData = ctx.getImageData(0, 0, 1, 1);
                    imageData.data[3] = imageData.data[3] === 255 ? 254 : 255;
                    ctx.putImageData(imageData, 0, 0);
                }
            } catch (e) {
                // Canvas may be tainted — ignore silently
            }
            return originalToDataURL.apply(this, arguments);
        };

        console.log("[Digital DNA] ✅ Canvas Noise Injection Active");

        // ════════════════════════════════════════════
        // SUMMARY
        // ════════════════════════════════════════════
        console.log(
            "%c[Digital DNA] 🧬 Shadow Profile Active\n" +
            `  → OS: ${SHADOW_PROFILE.platform} (Windows 10)\n` +
            `  → Browser: Chrome 120\n` +
            `  → Screen: ${SHADOW_PROFILE.screenWidth}x${SHADOW_PROFILE.screenHeight}\n` +
            `  → CPU: ${SHADOW_PROFILE.hardwareConcurrency} cores | RAM: ${SHADOW_PROFILE.deviceMemory}GB\n` +
            `  → Canvas: Noise injected`,
            "color: #00ff88; background: #0a0a1a; font-size: 11px; padding: 6px 10px; border-radius: 4px; border: 1px solid #00ff88;"
        );

    } catch (e) {
        console.warn("[Digital DNA] Injection partially failed:", e);
    }
})();
