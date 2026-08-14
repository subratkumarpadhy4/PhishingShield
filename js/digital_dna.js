/**
 * Oculus - Digital DNA (Shadow Profile Module)
 * Injected into the MAIN world execution environment at document_start.
 * Creates an authentic, undetectable synthetic Windows 10 / Chrome 120 profile.
 */
(function () {
    // 🛡️ CONFIGURATION: Shadow Profile Constants
    const SHADOW_PROFILE = {
        userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        appVersion: "5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        platform: "Win32",
        oscpu: "Windows NT 10.0; Win64; x64",
        vendor: "Google Inc.",
        hardwareConcurrency: 8, // 8 CPU cores
        deviceMemory: 8,        // 8GB RAM
        screenWidth: 1920,
        screenHeight: 1080,
        availWidth: 1920,
        availHeight: 1040,      // Minus Windows taskbar
        webglVendor: "Google Inc. (NVIDIA)",
        webglRenderer: "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 Direct3D11 vs_5_0 ps_5_0, D3D11)"
    };

    // User-Agent Client Hints (navigator.userAgentData)
    const shadowUserAgentData = {
        brands: [
            { brand: "Not_A Brand", version: "8" },
            { brand: "Chromium", version: "120" },
            { brand: "Google Chrome", version: "120" }
        ],
        mobile: false,
        platform: "Windows",
        getHighEntropyValues: function (hints) {
            return Promise.resolve({
                architecture: "x86",
                bitness: "64",
                brands: [
                    { brand: "Not_A Brand", version: "8" },
                    { brand: "Chromium", version: "120" },
                    { brand: "Google Chrome", version: "120" }
                ],
                fullVersionList: [
                    { brand: "Not_A Brand", version: "8.0.0.0" },
                    { brand: "Chromium", version: "120.0.6099.109" },
                    { brand: "Google Chrome", version: "120.0.6099.109" }
                ],
                mobile: false,
                model: "",
                platform: "Windows",
                platformVersion: "10.0.0",
                uaFullVersion: "120.0.6099.109"
            });
        },
        toJSON: function () {
            return {
                brands: this.brands,
                mobile: this.mobile,
                platform: this.platform
            };
        }
    };

    // =========================================================================
    // 1. NAVIGATOR OVERRIDES (PROTOTYPE + INSTANCE)
    // =========================================================================
    const navTargets = [
        typeof Navigator !== 'undefined' ? Navigator.prototype : null,
        typeof window !== 'undefined' ? window.navigator : null
    ].filter(Boolean);

    navTargets.forEach(target => {
        try {
            Object.defineProperty(target, 'userAgent', { get: () => SHADOW_PROFILE.userAgent, configurable: true, enumerable: true });
            Object.defineProperty(target, 'appVersion', { get: () => SHADOW_PROFILE.appVersion, configurable: true, enumerable: true });
            Object.defineProperty(target, 'platform', { get: () => SHADOW_PROFILE.platform, configurable: true, enumerable: true });
            Object.defineProperty(target, 'oscpu', { get: () => SHADOW_PROFILE.oscpu, configurable: true, enumerable: true });
            Object.defineProperty(target, 'vendor', { get: () => SHADOW_PROFILE.vendor, configurable: true, enumerable: true });
            Object.defineProperty(target, 'hardwareConcurrency', { get: () => SHADOW_PROFILE.hardwareConcurrency, configurable: true, enumerable: true });
            Object.defineProperty(target, 'deviceMemory', { get: () => SHADOW_PROFILE.deviceMemory, configurable: true, enumerable: true });
            Object.defineProperty(target, 'maxTouchPoints', { get: () => 0, configurable: true, enumerable: true });
            Object.defineProperty(target, 'userAgentData', { get: () => shadowUserAgentData, configurable: true, enumerable: true });
        } catch (e) { }
    });

    // =========================================================================
    // 2. SCREEN OVERRIDES (PROTOTYPE + INSTANCE)
    // =========================================================================
    const screenTargets = [
        typeof Screen !== 'undefined' ? Screen.prototype : null,
        typeof window !== 'undefined' ? window.screen : null
    ].filter(Boolean);

    screenTargets.forEach(target => {
        try {
            Object.defineProperty(target, 'width', { get: () => SHADOW_PROFILE.screenWidth, configurable: true, enumerable: true });
            Object.defineProperty(target, 'height', { get: () => SHADOW_PROFILE.screenHeight, configurable: true, enumerable: true });
            Object.defineProperty(target, 'availWidth', { get: () => SHADOW_PROFILE.availWidth, configurable: true, enumerable: true });
            Object.defineProperty(target, 'availHeight', { get: () => SHADOW_PROFILE.availHeight, configurable: true, enumerable: true });
            Object.defineProperty(target, 'colorDepth', { get: () => 24, configurable: true, enumerable: true });
            Object.defineProperty(target, 'pixelDepth', { get: () => 24, configurable: true, enumerable: true });
        } catch (e) { }
    });

    // =========================================================================
    // 3. WEBGL GPU & RENDERER SPOOFING
    // =========================================================================
    const UNMASKED_VENDOR_WEBGL = 0x9245;
    const UNMASKED_RENDERER_WEBGL = 0x9246;

    function hookWebGL(glProto) {
        if (!glProto || !glProto.getParameter) return;
        const originalGetParameter = glProto.getParameter;
        glProto.getParameter = function (parameter) {
            if (parameter === UNMASKED_VENDOR_WEBGL) {
                return SHADOW_PROFILE.webglVendor;
            }
            if (parameter === UNMASKED_RENDERER_WEBGL) {
                return SHADOW_PROFILE.webglRenderer;
            }
            return originalGetParameter.apply(this, arguments);
        };
    }

    if (typeof WebGLRenderingContext !== 'undefined') hookWebGL(WebGLRenderingContext.prototype);
    if (typeof WebGL2RenderingContext !== 'undefined') hookWebGL(WebGL2RenderingContext.prototype);

    // =========================================================================
    // 4. CANVAS NOISE INJECTION
    // =========================================================================
    if (typeof HTMLCanvasElement !== 'undefined') {
        const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
        HTMLCanvasElement.prototype.toDataURL = function () {
            try {
                const ctx = this.getContext('2d');
                if (ctx && this.width > 0 && this.height > 0) {
                    const imgData = ctx.getImageData(0, 0, 1, 1);
                    imgData.data[0] = (imgData.data[0] + 1) % 256;
                    ctx.putImageData(imgData, 0, 0);
                }
            } catch (e) { }
            return originalToDataURL.apply(this, arguments);
        };
    }

    if (typeof CanvasRenderingContext2D !== 'undefined') {
        const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
        CanvasRenderingContext2D.prototype.getImageData = function () {
            const res = originalGetImageData.apply(this, arguments);
            if (res && res.data && res.data.length > 3) {
                res.data[0] = (res.data[0] + 1) % 256;
            }
            return res;
        };
    }

    // =========================================================================
    // 5. AUDIO FINGERPRINTING NOISE
    // =========================================================================
    if (typeof AudioBuffer !== 'undefined') {
        const originalGetChannelData = AudioBuffer.prototype.getChannelData;
        AudioBuffer.prototype.getChannelData = function () {
            const channelData = originalGetChannelData.apply(this, arguments);
            if (channelData && channelData.length > 0) {
                channelData[0] += 0.0000001;
            }
            return channelData;
        };
    }

    console.log(
        "%c[Oculus] 🧬 Shadow Profile Active (Windows 10 / Chrome 120 / GTX 1660)",
        "color: #10b981; background: #0f172a; font-size: 11px; font-weight: bold; padding: 4px 8px; border-radius: 4px; border: 1px solid #10b981;"
    );
})();
