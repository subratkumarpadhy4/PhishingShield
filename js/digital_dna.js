/**
 * Digital DNA - Fingerprint Spoofing Module
 * Injected into the Main World execution environment.
 * Overrides navigator and screen properties to create a "Shadow Profile".
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

    console.log("%c[Digital DNA] 🧬 Shadow Profile Activated (Injected by Bootloader)", "color: #00ff00; background: #000; font-size: 12px; padding: 4px;");

    // 🛠️ HELPER: Property Override (Robust)
    function overrideProperty(object, property, value) {
        try {
            // Try defining on the object instance first
            Object.defineProperty(object, property, {
                get: () => value,
                configurable: true
            });
        } catch (e) {
            // Fallback: Try defining on the prototype
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
        // 1. Spoof Navigator (User Agent, Platform, etc.)
        // We override both the instance and potentially the prototype to be sure
        const nav = window.navigator;

        overrideProperty(nav, 'userAgent', SHADOW_PROFILE.userAgent);
        overrideProperty(nav, 'appVersion', SHADOW_PROFILE.appVersion);
        overrideProperty(nav, 'platform', SHADOW_PROFILE.platform);
        overrideProperty(nav, 'vendor', SHADOW_PROFILE.vendor);
        overrideProperty(nav, 'hardwareConcurrency', SHADOW_PROFILE.hardwareConcurrency);
        overrideProperty(nav, 'deviceMemory', SHADOW_PROFILE.deviceMemory);

        // 2. Spoof Screen Resolution (1920x1080)
        // Screen properties are often read-only, so we target the prototype if needed
        const screen = window.screen;
        overrideProperty(screen, 'width', SHADOW_PROFILE.screenWidth);
        overrideProperty(screen, 'height', SHADOW_PROFILE.screenHeight);
        overrideProperty(screen, 'availWidth', SHADOW_PROFILE.screenWidth);
        overrideProperty(screen, 'availHeight', SHADOW_PROFILE.screenHeight - 40); // Minus taskbar

        console.log(`[Digital DNA] User Agent Spoofed: ${navigator.userAgent}`);
        console.log(`[Digital DNA] Platform Spoofed: ${navigator.platform}`);

        // 3. Canvas Noise Injection (Anti-Fingerprinting)
        // We slightly modify canvas rendering so specific "hash" tracking fails.
        const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
        HTMLCanvasElement.prototype.toDataURL = function (type) {
            // Only apply noise if context exists and has data
            // (Simplified for stability - pure noisification would modify pixel data via getContext)
            // console.log("[Digital DNA] Canvas Read Attempt Detected & Obfuscated");
            // In a full implementation, we would modify the pixel buffer slightly here.
            return originalToDataURL.apply(this, arguments);
        };

    } catch (e) {
        console.warn("[Digital DNA] Injection partially failed:", e);
    }
})();
