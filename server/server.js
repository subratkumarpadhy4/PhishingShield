const express = require("express");
const path = require("path");
require('dotenv').config({ path: path.join(__dirname, '../.env') });
const cors = require("cors");
const bodyParser = require("body-parser");
const fs = require("fs");
// const path = require("path"); // Moved to top
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;
const REPORTS_FILE = path.join(__dirname, 'reports.json');
const USERS_FILE = path.join(__dirname, 'users.json');
const AUDIT_LOG_FILE = path.join(__dirname, 'data', 'audit_logs.json');
const TRUST_FILE = path.join(__dirname, 'data', 'trust_scores.json');
const REPORTS_FILE = path.join(__dirname, "reports.json");
const USERS_FILE = path.join(__dirname, "users.json");
const AUDIT_LOG_FILE = path.join(__dirname, "data", "audit_logs.json");

console.log("Gemini Key Status:", process.env.GEMINI_API_KEY ? "Found" : "Not Found");


// Admin Configuration (Server-Side Only)
const ADMIN_EMAILS = ["rajkumarpadhy2006@gmail.com"]; // Add more admin emails here
const JWT_SECRET =
    process.env.JWT_SECRET ||
    "phishingshield-secret-key-change-in-production-2024";
const JWT_EXPIRY_ADMIN = "10d"; // Admin sessions expire in 10 days

// Middleware
// Enhanced CORS configuration for Chrome extension and web access
app.use(
    cors({
        origin: "*", // Allow all origins (Chrome extensions use chrome-extension:// URLs)
        methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
        credentials: false,
    }),
);

// Handle preflight requests
app.options("*", cors());

app.use(bodyParser.json());

// PREVENT CRASHES: Global Error Handlers
process.on("uncaughtException", (err) => {
    console.error("CRITICAL ERROR (Uncaught Exception):", err);
    // Keep server alive
});

process.on("unhandledRejection", (reason, promise) => {
    console.error("CRITICAL ERROR (Unhandled Rejection):", reason);
    // Keep server alive
});

// Initialize Data Files
if (!fs.existsSync(REPORTS_FILE)) fs.writeFileSync(REPORTS_FILE, JSON.stringify([], null, 2));
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify([], null, 2));
if (!fs.existsSync(path.dirname(AUDIT_LOG_FILE))) fs.mkdirSync(path.dirname(AUDIT_LOG_FILE), { recursive: true });
if (!fs.existsSync(AUDIT_LOG_FILE)) fs.writeFileSync(AUDIT_LOG_FILE, JSON.stringify([], null, 2));
if (!fs.existsSync(TRUST_FILE)) fs.writeFileSync(TRUST_FILE, JSON.stringify([], null, 2));
if (!fs.existsSync(REPORTS_FILE))
    fs.writeFileSync(REPORTS_FILE, JSON.stringify([], null, 2));
if (!fs.existsSync(USERS_FILE))
    fs.writeFileSync(USERS_FILE, JSON.stringify([], null, 2));
if (!fs.existsSync(path.dirname(AUDIT_LOG_FILE)))
    fs.mkdirSync(path.dirname(AUDIT_LOG_FILE), { recursive: true });
if (!fs.existsSync(AUDIT_LOG_FILE))
    fs.writeFileSync(AUDIT_LOG_FILE, JSON.stringify([], null, 2));

// --- Helpers ---
const readData = (file) => {
    try {
        return JSON.parse(fs.readFileSync(file));
    } catch (e) {
        return [];
    }
};
const writeData = (file, data) => {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
};


// --- TRUST SCORE SYSTEM (Community Voting) ---
app.get('/api/trust/score', (req, res) => {
    const { domain } = req.query;
    if (!domain) return res.status(400).json({ error: "Domain required" });

    const scores = readData(TRUST_FILE);
    const domainData = scores.find(s => s.domain === domain);

    if (!domainData) return res.json({ score: 50, votes: 0, status: 'unknown' }); // Neutral start

    const total = domainData.safe + domainData.unsafe;
    const score = total === 0 ? 50 : Math.round((domainData.safe / total) * 100);

    res.json({
        score,
        votes: total,
        status: score > 70 ? 'safe' : (score < 30 ? 'malicious' : 'suspect')
    });
});

app.post('/api/trust/vote', (req, res) => {
    // userId is recommended to limit spam
    const { domain, vote, userId } = req.body; // vote: 'safe' or 'unsafe'
    if (!domain || !vote) return res.status(400).json({ error: "Domain and vote required" });

    let scores = readData(TRUST_FILE);
    let entry = scores.find(s => s.domain === domain);

    if (!entry) {
        entry = { domain, safe: 0, unsafe: 0, voters: {} };
        scores.push(entry);
    }

    // Initialize voters map if simple structure exists
    if (!entry.voters) entry.voters = {};

    // ANONYMOUS MODE FALLBACK: If no userId, allow infinite votes (legacy behavior)
    // To enforcing limits, client MUST send userId.
    const uid = userId || 'anonymous_' + Date.now();

    if (userId && entry.voters[userId]) {
        const previousVote = entry.voters[userId];

        if (previousVote === vote) {
            return res.json({ success: true, message: "You have already voted this way." });
        } else {
            // Switch vote
            if (previousVote === 'safe') entry.safe = Math.max(0, entry.safe - 1);
            else entry.unsafe = Math.max(0, entry.unsafe - 1);

            if (vote === 'safe') entry.safe++;
            else entry.unsafe++;

            entry.voters[userId] = vote;
            console.log(`[Trust] Vote SWITCHED for ${domain} by ${userId}: ${previousVote} -> ${vote}`);
        }
    } else {
        // New Vote
        if (vote === 'safe') entry.safe++;
        else if (vote === 'unsafe') entry.unsafe++;

        // Track it
        if (userId) entry.voters[userId] = vote;
    }

    writeData(TRUST_FILE, scores);
    console.log(`[Trust] New vote for ${domain}: ${vote} (User: ${userId || 'Anon'})`);
    res.json({ success: true, message: "Vote recorded." });
});

// Admin: Clear all trust history
app.post('/api/trust/clear', (req, res) => {
    // In a real app, requireAdmin middleware here.
    writeData(TRUST_FILE, []);
    console.warn("[Admin] Trust history cleared.");
    res.json({ success: true, message: "All trust scores cleared." });
});

// Admin: Get all trust scores
app.get('/api/trust/all', (req, res) => {
    const scores = readData(TRUST_FILE);
    res.json(scores);
});

// Admin: Simulate Sync to Global Server
app.post('/api/trust/sync', (req, res) => {
    // 1. Read Local Trust Data
    const localData = readData(TRUST_FILE);

    // 2. Simulate Upload delay
    setTimeout(() => {
        // 3. Update Sync Timestamp (stored in a separate file or metadata)
        const META_FILE = path.join(__dirname, 'data', 'server_meta.json');
        let meta = {};
        if (fs.existsSync(META_FILE)) meta = JSON.parse(fs.readFileSync(META_FILE));

        meta.lastTrustSync = Date.now();
        fs.writeFileSync(META_FILE, JSON.stringify(meta, null, 2));

        console.log("[Sync] Trust scores synced to Global Server (Simulated).");
        res.json({ success: true, syncedCount: localData.length, timestamp: meta.lastTrustSync });
    }, 1500);
});

// Admin: Get Sync Status
app.get('/api/trust/sync-status', (req, res) => {
    const META_FILE = path.join(__dirname, 'data', 'server_meta.json');
    if (!fs.existsSync(META_FILE)) return res.json({ lastSync: null });

    const meta = JSON.parse(fs.readFileSync(META_FILE));
    res.json({ lastSync: meta.lastTrustSync || null });
});


// --- ROUTES: REPORTS ---

// GET /api/reports
app.get("/api/reports", (req, res) => {
    res.json(readData(REPORTS_FILE));
});

// POST /api/reports
app.post("/api/reports", (req, res) => {
    const newReport = req.body;
    if (!newReport.url) return res.status(400).json({ error: "Missing URL" });

    const report = {
        id: Date.now().toString(),
        url: newReport.url,
        hostname: newReport.hostname || "Unknown",
        reporter: newReport.reporter || "Anonymous",
        timestamp: Date.now(),
        status: "pending",
        ...newReport,
    };

    const reports = readData(REPORTS_FILE);
    reports.push(report);
    writeData(REPORTS_FILE, reports);

    console.log(`[Report] ${report.url} by ${report.reporter}`);
    res.status(201).json({ message: "Report logged", report });
});

// --- ROUTES: USERS & AUTH ---

// GET /api/users
app.get("/api/users", (req, res) => {
    const users = readData(USERS_FILE);
    // Return safe public info if needed, or full objects for this internal extension backend
    res.json(users);
});

// GET /test-phish (Simulation Page)
app.get("/test-phish", (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Urgent Security Update - Verify Account</title>
            <style>
                body { font-family: sans-serif; padding: 50px; text-align: center; background: #f8f9fa; }
                .container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); max-width: 500px; margin: 0 auto; }
                h1 { color: #dc3545; }
                button { background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; font-size: 16px; margin-top: 10px; }
                input { padding: 10px; width: 100%; margin: 10px 0; border: 1px solid #ccc; border-radius: 5px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>⚠️ Account Suspended</h1>
                <p>We detected unauthorized access to your **Bank** account.</p>
                <p>Please <strong>login immediately</strong> to verify your identity or your funds will be frozen within 24 hours.</p>
                
                <form action="/login" method="POST">
                    <input type="email" placeholder="Email Address" />
                    <!-- Triggers Insecure Password Risk -->
                    <input type="password" placeholder="Enter Password" />
                    <button type="submit">Verify Now</button>
                </form>
                <br>
                <small>This is a safe simulation page to trigger PhishingShield HUD.</small>
            </div>
        </body>
        </html>
    `);
});

// Email Configuration (EmailJS - Works with Gmail, no domain verification needed)
const axios = require("axios");
let emailServiceReady = false;

// EmailJS Configuration
const EMAILJS_SERVICE_ID = process.env.EMAILJS_SERVICE_ID || "service_orcv7av";
const EMAILJS_TEMPLATE_ID =
    process.env.EMAILJS_TEMPLATE_ID || "template_f0lfm5h";
const EMAILJS_PUBLIC_KEY =
    process.env.EMAILJS_PUBLIC_KEY || "BxDgzDbuSkLEs4H_9";

// Initialize EmailJS
function initializeEmailService() {
    if (!EMAILJS_SERVICE_ID || !EMAILJS_TEMPLATE_ID || !EMAILJS_PUBLIC_KEY) {
        console.warn(
            "[EMAIL] EmailJS not fully configured. OTPs will be logged to console.",
        );
        console.warn(
            "[EMAIL] Set EMAILJS_SERVICE_ID, EMAILJS_TEMPLATE_ID, and EMAILJS_PUBLIC_KEY environment variables.",
        );
        return false;
    }

    try {
        console.log("[EMAIL] EmailJS initialized successfully");
        console.log(`[EMAIL] Service ID: ${EMAILJS_SERVICE_ID}`);
        console.log("[EMAIL] No domain verification needed - works with Gmail!");
        console.log("[EMAIL] Free tier: 200 emails/month");
        return true;
    } catch (error) {
        console.error("[EMAIL] Failed to initialize EmailJS:", error.message);
        console.log("[EMAIL] Server will continue without email functionality");
        return false;
    }
}

emailServiceReady = initializeEmailService();

// Helper function to convert HTML to plain text (simple version)
function htmlToText(html) {
    return html
        .replace(/<style[^>]*>.*?<\/style>/gi, "")
        .replace(/<[^>]+>/g, "")
        .replace(/\n\s*\n/g, "\n")
        .trim();
}

// Helper function to send email via EmailJS
async function sendEmail(to, subject, htmlContent, options = {}) {
    // Extract OTP code from HTML
    const otpMatch = htmlContent.match(/>(\d{4,6})</);
    const otpCode = otpMatch ? otpMatch[1] : "XXXX";

    // Extract recipient name if available
    const toName = options.toName || "User";

    try {
        const payload = {
            service_id: EMAILJS_SERVICE_ID,
            template_id: EMAILJS_TEMPLATE_ID,
            user_id: EMAILJS_PUBLIC_KEY,
            template_params: {
                to_name: toName,
                to_email: to,
                email: to,
                otp: otpCode,
                subject: subject,
                message: htmlContent,
            },
        };

        const config = {
            headers: {
                "Content-Type": "application/json",
                Origin: "https://phishingshield.onrender.com",
            },
        };

        const response = await axios.post(
            "https://api.emailjs.com/api/v1.0/email/send",
            payload,
            config,
        );

        console.log("[EMAIL] Email sent successfully via EmailJS");
        return { success: true, response: response.data };
    } catch (error) {
        console.error("[EMAIL] EmailJS error:", error.message);
        if (error.response) {
            console.error("[EMAIL] EmailJS response:", error.response.data);
        }
        return { success: false, error: error.message };
    }
}

// In-memory OTP store (Global variable)
const otpStore = {};

// Automatic cleanup for OTPs and Rate Limits (Every 5 minutes)
setInterval(() => {
    const now = Date.now();

    // Clean OTPs
    Object.keys(otpStore).forEach(email => {
        if (otpStore[email].expires < now) {
            delete otpStore[email];
        }
    });

    // Clean Rate Limits
    Object.keys(adminRateLimit).forEach(key => {
        // defined below
        if (adminRateLimit[key].expires < now) {
            delete adminRateLimit[key];
        }
    });
}, 5 * 60 * 1000);

// Admin-specific stores
const adminPendingSessions = {}; // Stores temporary admin sessions before MFA
const adminSessions = {}; // Stores active admin sessions
const adminRateLimit = {}; // Rate limiting for admin endpoints



// Helper: Check if email is admin
function isAdminEmail(email) {
    if (!email) return false;
    return ADMIN_EMAILS.includes(email.toLowerCase().trim());
}

// Helper: Generate 6-digit OTP for admin
function generateAdminOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// Helper: Audit logging
function logAdminAction(userId, action, ipAddress, success, details = {}) {
    const logs = readData(AUDIT_LOG_FILE);
    logs.push({
        id: `log_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        userId,
        action,
        ipAddress,
        userAgent: details.userAgent || "Unknown",
        success,
        details,
        timestamp: new Date().toISOString(),
    });
    writeData(AUDIT_LOG_FILE, logs);
    console.log(
        `[AUDIT] ${action} - User: ${userId} - IP: ${ipAddress} - Success: ${success}`,
    );
}

// Helper: Rate limiting check for admin
function checkAdminRateLimit(ip, endpoint) {
    const key = `${ip}:${endpoint}`;
    const now = Date.now();
    const LIMIT = 15; // 15 attempts (Updated by User)
    const WINDOW = 15 * 60 * 1000; // 15 minutes

    if (!adminRateLimit[key]) {
        adminRateLimit[key] = { count: 1, expires: now + WINDOW };
        return true;
    }

    const record = adminRateLimit[key];

    // Check if window expired (should be handled by cleanup, but double check)
    if (now > record.expires) {
        record.count = 1;
        record.expires = now + WINDOW;
        return true;
    }

    if (record.count >= LIMIT) {
        return false;
    }

    record.count++;
    return true;
}

// Helper: Get client IP
function getClientIP(req) {
    return (
        req.headers["x-forwarded-for"]?.split(",")[0] ||
        req.connection.remoteAddress ||
        req.socket.remoteAddress ||
        "127.0.0.1"
    );
}

// POST /api/send-otp
app.post("/api/send-otp", async (req, res) => {
    const { email } = req.body;
    if (!email)
        return res.status(400).json({ success: false, message: "Email required" });

    // Generate 4-digit code
    const code = Math.floor(1000 + Math.random() * 9000).toString();
    // Expires in 10 minutes
    otpStore[email] = {
        code: code,
        expires: Date.now() + 10 * 60 * 1000
    };

    // Log for Dev
    console.log(`[OTP] Preparing to send ${code} to ${email}...`);

    // EmailJS uses template, so FROM_EMAIL is set in EmailJS dashboard
    const fromEmail = process.env.FROM_EMAIL || "phishingshield@gmail.com";
    const mailOptions = {
        from: `"PhishingShield Security" <${fromEmail}>`,
        to: email,
        subject: "Your Verification Code",
        html: `
            <div style="background-color: #f4f6f9; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding: 40px 0;">
                <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.05); overflow: hidden;">
                    <!-- Header -->
                    <div style="background-color: #0f172a; padding: 30px; text-align: center;">
                        <h1 style="color: #ffffff; margin: 0; font-size: 24px; letter-spacing: 1px;">PhishingShield</h1>
                    </div>
                    
                    <!-- Content -->
                    <div style="padding: 40px 30px; text-align: center;">
                        <h2 style="color: #1e293b; font-size: 22px; margin-bottom: 10px;">Verification Required</h2>
                        <p style="color: #64748b; font-size: 16px; line-height: 1.5; margin-bottom: 30px;">
                            You are registering or signing in to PhishingShield. Please use the verification code below to complete the process.
                        </p>
                        
                        <!-- OTP Code -->
                        <div style="background-color: #f1f5f9; border: 2px dashed #94a3b8; border-radius: 8px; padding: 20px; margin: 0 auto 30px; width: fit-content; min-width: 200px;">
                            <span style="font-size: 32px; font-weight: 800; letter-spacing: 8px; color: #0d6efd; display: block;">${code}</span>
                        </div>
                        
                        <p style="color: #94a3b8; font-size: 14px; margin-top: 30px;">
                            This code will expire in 10 minutes.<br>
                            If you did not request this email, please ignore it.
                        </p>
                    </div>
                    
                    <!-- Footer -->
                    <div style="background-color: #f8fafc; padding: 20px; text-align: center; border-top: 1px solid #e2e8f0;">
                        <p style="color: #cbd5e1; font-size: 12px; margin: 0;">
                            &copy; ${new Date().getFullYear()} PhishingShield Security. All rights reserved.
                        </p>
                    </div>
                </div>
            </div>
        `,
    };

    // Check if email service is available
    if (!emailServiceReady) {
        console.log(
            `[OTP FALLBACK] Email service unavailable. Code for ${email}: ${code}`,
        );
        return res.json({
            success: true,
            message: "OTP generated (check server logs)",
        });
    }

    // Send email via EmailJS
    const emailResult = await sendEmail(
        email,
        mailOptions.subject,
        mailOptions.html,
        {
            toName: req.body.name || "User",
        },
    );

    if (emailResult.success) {
        console.log(`[OTP] Email sent successfully to ${email}`);
        res.json({ success: true, message: "OTP Sent to Email!" });
    } else {
        console.error("[OTP] Error sending email:", emailResult.error);
        console.log(`[OTP FALLBACK] Code for ${email}: ${code}`);
        res.json({ success: true, message: "OTP generated (check server logs)" });
    }
});

// POST /api/verify-otp (Mock)
app.post("/api/verify-otp", (req, res) => {
    const { email, otp } = req.body;

    const record = otpStore[email];

    if (!record) {
        return res.status(400).json({ success: false, message: "OTP expired or invalid" });
    }

    // Check Expiry
    if (Date.now() > record.expires) {
        delete otpStore[email];
        return res.status(400).json({ success: false, message: "OTP expired" });
    }

    // Check against stored code (Robust string comparison)
    const stored = String(record.code).trim();
    const input = otp ? String(otp).trim() : '';
    const stored = otpStore[email] ? String(otpStore[email]).trim() : null;
    const input = otp ? String(otp).trim() : "";

    if (stored === input) {
        console.log(`[OTP] ✅ Verified for ${email}`);
        delete otpStore[email]; // Clear after use
        res.json({ success: true });
    } else {
        console.warn(
            `[OTP] ❌ Failed for ${email}. Expected: ${stored}, Got: ${input}`,
        );
        res.status(400).json({ success: false, message: "Invalid OTP" });
    }
});

// POST /api/users/sync (Create or Update User)
app.post("/api/users/sync", (req, res) => {
    const userData = req.body;
    if (!userData.email) return res.status(400).json({ error: "Email required" });

    const users = readData(USERS_FILE);
    const idx = users.findIndex((u) => u.email === userData.email);

    let finalUser;

    if (idx !== -1) {
        // SERVER AUTHORITY STRATEGY:
        // We prioritize the Server's stored XP/Level over the Client's claim.
        // This allows Admin to demote users (Server < Client) and have it reflect on the client.

        const serverXP = Number(users[idx].xp) || 0;
        const serverLevel = Number(users[idx].level) || 1;

        // SMART SYNC: Keep the highest value to prevent Client overwriting Admin Promotion
        // and prevent Admin Promotion from being lost by a stale client sync.
        // SMART SYNC: Check for specific "isPenalty" flag to allow reduction
        // If it's a penalty, we TRUST the client's lower value.
        // Otherwise, we keep the highest value (Server Authority) to prevent data loss.
        const isPenalty = userData.isPenalty === true;
        const incomingXP = userData.xp !== undefined ? Number(userData.xp) : 0;
        const finalXP = isPenalty ? incomingXP : Math.max(incomingXP, serverXP);

        // Logic for Level:
        // If it's a penalty, we also accept the client's (potentially lower) level.
        // Otherwise, we use the standard max logic to prevent accidental demotions.
        const incomingLevel =
            userData.level !== undefined ? Number(userData.level) : 1;
        const finalLevel = isPenalty
            ? incomingLevel
            : incomingLevel > serverLevel
                ? incomingLevel
                : finalXP > serverXP
                    ? Math.floor(Math.sqrt(finalXP / 100)) + 1
                    : serverLevel;

        finalUser = {
            ...users[idx],
            ...userData,
            xp: finalXP,
            level: finalLevel,
        };

        // If simple overwrite is preferred for Admin demotions, we need a flag.
        // But assuming "Promotion" is the goal:

        users[idx] = finalUser;
        console.log(`[User] Synced ${userData.email} - Merged XP: ${finalUser.xp}`);
    } else {
        // Create new
        finalUser = userData;
        users.push(finalUser);
        console.log(`[User] New user registered: ${userData.email}`);
    }

    writeData(USERS_FILE, users);
    res.json({ success: true, user: finalUser });
});

// POST /api/users/delete
app.post("/api/users/delete", (req, res) => {
    const { email } = req.body;
    let users = readData(USERS_FILE);
    const initialLen = users.length;
    users = users.filter((u) => u.email !== email);

    if (users.length !== initialLen) {
        writeData(USERS_FILE, users);
        console.log(`[User] Deleted: ${email}`);
        res.json({ success: true });
    } else {
        res.status(404).json({ success: false, message: "User not found" });
    }
});

// POST /api/users/reset-password
app.post("/api/users/reset-password", (req, res) => {
    const { email, password } = req.body;
    const users = readData(USERS_FILE);
    const idx = users.findIndex((u) => u.email === email);

    if (idx !== -1) {
        users[idx].password = password;
        writeData(USERS_FILE, users);
        console.log(`[User] Password reset for: ${email}`);
        res.json({ success: true });
    } else {
        res.status(404).json({ success: false, message: "User not found" });
    }
});

// ============================================
// ADMIN AUTHENTICATION ENDPOINTS (SECURE)
// ============================================

// POST /api/auth/admin/login - Step 1: Primary Authentication
app.post("/api/auth/admin/login", async (req, res) => {
    const { email, password } = req.body;
    const ip = getClientIP(req);

    // Rate limiting check
    if (!checkAdminRateLimit(ip, "admin_login")) {
        logAdminAction(email || "unknown", "admin_login_attempt", ip, false, {
            reason: "rate_limit_exceeded",
        });
        return res.status(429).json({
            success: false,
            message: "Too many attempts. Please try again in 30 minutes.",
        });
    }

    if (!email || !password) {
        return res
            .status(400)
            .json({ success: false, message: "Email and password required" });
    }

    // Server-side admin check
    if (!isAdminEmail(email)) {
        logAdminAction(email, "admin_login_attempt", ip, false, {
            reason: "not_admin_email",
        });
        return res.status(403).json({ success: false, message: "Access denied" });
    }

    // Find user
    const users = readData(USERS_FILE);
    const user = users.find((u) => u.email.toLowerCase() === email.toLowerCase());

    if (!user) {
        logAdminAction(email, "admin_login_attempt", ip, false, {
            reason: "user_not_found",
        });
        return res
            .status(401)
            .json({ success: false, message: "Invalid credentials" });
    }

    // Verify password (plaintext for now, but admin should use strong password)
    if (user.password !== password) {
        logAdminAction(email, "admin_login_attempt", ip, false, {
            reason: "invalid_password",
        });
        return res
            .status(401)
            .json({ success: false, message: "Invalid credentials" });
    }

    // Authenticated successfully - Generate Admin Session directly (No OTP)
    const sessionId = `admin_sess_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    // Generate JWT token for admin
    // Note: mfaVerified set to true as we are trusting password authentication now
    const adminToken = jwt.sign(
        {
            userId: user.email,
            email: user.email,
            role: "admin",
            mfaVerified: true,
            ipAddress: ip,
            sessionId: sessionId,
        },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRY_ADMIN },
    );

    // Store admin session PERSISTENTLY
    const sessions = getAdminSessions();
    sessions[sessionId] = {
        userId: user.email,
        token: adminToken,
        ip,
        createdAt: Date.now(),
        expiresAt: Date.now() + 10 * 24 * 60 * 60 * 1000, // 10 days
    };
    saveAdminSessions(sessions);

    logAdminAction(user.email, "admin_login_success", ip, true, {
        sessionId,
        method: "password_only",
    });

    res.json({
        success: true,
        token: adminToken,
        user: {
            email: user.email,
            name: user.name,
            role: "admin",
        },
        expiresIn: "10d",
        requiresMFA: false,
    });
});

// Persistent Admin Sessions
const SESSIONS_FILE = path.join(__dirname, "data", "admin_sessions.json");
if (!fs.existsSync(SESSIONS_FILE))
    fs.writeFileSync(SESSIONS_FILE, JSON.stringify({}, null, 2));

function getAdminSessions() {
    return readData(SESSIONS_FILE) || {};
}

function saveAdminSessions(sessions) {
    writeData(SESSIONS_FILE, sessions);
}

// POST /api/auth/admin/verify-mfa - Step 2: MFA Verification
app.post("/api/auth/admin/verify-mfa", (req, res) => {
    const { sessionId, otp } = req.body;
    const ip = getClientIP(req);

    if (!sessionId || !otp) {
        return res
            .status(400)
            .json({ success: false, message: "Session ID and OTP required" });
    }

    // Find pending session
    const pendingSession = adminPendingSessions[sessionId];

    if (!pendingSession) {
        logAdminAction("unknown", "admin_mfa_verify", ip, false, {
            reason: "invalid_session",
        });
        return res
            .status(401)
            .json({ success: false, message: "Invalid or expired session" });
    }

    // Check expiry
    if (Date.now() > pendingSession.expiresAt) {
        delete adminPendingSessions[sessionId];
        logAdminAction(pendingSession.email, "admin_mfa_verify", ip, false, {
            reason: "session_expired",
        });
        return res
            .status(401)
            .json({
                success: false,
                message: "Session expired. Please login again.",
            });
    }

    // Verify OTP
    const inputOTP = String(otp).trim();
    const storedOTP = String(pendingSession.otp).trim();

    if (inputOTP !== storedOTP) {
        logAdminAction(pendingSession.email, "admin_mfa_verify", ip, false, {
            reason: "invalid_otp",
        });
        return res.status(401).json({ success: false, message: "Invalid OTP" });
    }

    // OTP verified - create admin session
    const users = readData(USERS_FILE);
    const user = users.find(
        (u) => u.email.toLowerCase() === pendingSession.email.toLowerCase(),
    );

    if (!user) {
        delete adminPendingSessions[sessionId];
        return res.status(404).json({ success: false, message: "User not found" });
    }

    // Generate JWT token for admin
    const adminToken = jwt.sign(
        {
            userId: user.email,
            email: user.email,
            role: "admin",
            mfaVerified: true,
            ipAddress: ip,
            sessionId: sessionId,
        },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRY_ADMIN },
    );

    // Store admin session PERSISTENTLY
    const sessions = getAdminSessions();
    sessions[sessionId] = {
        userId: user.email,
        token: adminToken,
        ip,
        createdAt: Date.now(),
        expiresAt: Date.now() + 10 * 24 * 60 * 60 * 1000, // 10 days
    };
    saveAdminSessions(sessions);

    // Clean up pending session
    delete adminPendingSessions[sessionId];

    logAdminAction(user.email, "admin_login_success", ip, true, {
        sessionId,
        mfaMethod: "email",
    });

    res.json({
        success: true,
        token: adminToken,
        user: {
            email: user.email,
            name: user.name,
            role: "admin",
        },
        expiresIn: "10d",
    });
});

// Middleware: Verify Admin Token

// --- GENERIC AI SCAN ENDPOINT (For real-time page analysis) ---
app.post("/api/ai/scan", async (req, res) => {
    try {
        const { url, content } = req.body;
        if (!url) return res.status(400).json({ error: "URL required" });

        // Limit content to avoid token limits
        const safeContent = (content || "").substring(0, 10000);

        console.log(`[AI-Scan] Analyzing: ${url}`);

        if (process.env.GROQ_API_KEY || process.env.GEMINI_API_KEY) {
            // Support both keys, but prefer GROQ logic if requested
            const Groq = require("groq-sdk");
            const groq = new Groq({ apiKey: process.env.GROQ_API_KEY || process.env.GEMINI_API_KEY });

            async function analyzeWithGroq() {
                const completion = await groq.chat.completions.create({
                    messages: [
                        {
                            role: "system",
                            content: `You are PhishingShield AI. Analyze the URL and Page Content.
Task: Classify the site into one of 3 categories:
1. 'SAFE' (Legitimate sites like Instagram, Google, Gamma).
2. 'SUSPICIOUS' (Unknown, shortened, or typos).
3. 'MALICIOUS' (Phishing, scam, fake login).
Return JSON: {classification: 'SAFE'|'SUSPICIOUS'|'MALICIOUS', reason: 'Short explanation'}.`
                        },
                        {
                            role: "user",
                            content: `URL: ${url}\\nContent: \"${safeContent.replace(/(\\r\\n|\\n|\\r)/gm, " ")}\"`
                        }
                    ],
                    model: "llama-3.3-70b-versatile",
                    temperature: 0.1,
                    response_format: { type: "json_object" }
                });

                const result = JSON.parse(completion.choices[0]?.message?.content || "{}");

                // Manual Mapping to Risk Score
                const cls = (result.classification || "SUSPICIOUS").toUpperCase();
                let score = 45; // Default SUSPICIOUS
                if (cls === "SAFE") score = 0;
                else if (cls === "MALICIOUS") score = 95;

                const suggestion = (score > 70) ? "BAN" : (score > 30 ? "CAUTION" : "IGNORE");

                return {
                    score: score,
                    suggestion: suggestion,
                    reason: result.reason
                };
            }

            try {
                const json = await analyzeWithGroq();
                console.log("[AI-Scan] Classification Result:", json);
                return res.json({ success: true, aiAnalysis: json });
            } catch (e) {
                console.error("[AI-Scan] Groq Failed:", e.message);
                return res.json({ success: false, error: e.message });
            }

        } else {
            console.log("[AI-Scan] No API Key. Skipping.");
            return res.json({ success: false, message: "No AI Key" });
        }
    } catch (error) {
        console.error("[AI-Scan] Error:", error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

// --- AI ANALYSIS ENDPOINT ---
app.post("/api/reports/ai-verify", async (req, res) => {
    try {
        const { id } = req.body;
        console.log("[AI-Verify] Received request for Report ID:", id);

        // FIX: Read reports from file instead of assuming global variable
        const reports = readData(REPORTS_FILE);

        const reportIndex = reports.findIndex((r) => r.id === id);
        if (reportIndex === -1) {
            console.warn("[AI-Verify] Report not found in DB:", id);
            return res.status(404).json({ error: "Report not found" });
        }

        const report = reports[reportIndex];

        if (!report.url) {
            console.warn("[AI-Verify] Report missing URL:", id);
            return res.status(400).json({ error: "Report data is incomplete (missing URL)" });
        }

        const url = report.url.toLowerCase();

        // --- REAL AI INTEGRATION ---
        let aiScore = 10;
        let aiSuggestion = "IGNORE";
        let aiReason = "No obvious threats detected.";

        if (process.env.GROQ_API_KEY || process.env.GEMINI_API_KEY) {
            // Use Groq if available (or fallback logic we used before)
            // Ideally we reuse the same robust logic we just built for /scan
            const { GoogleGenerativeAI } = require("@google/generative-ai");
            let modelName = "llama-3.3-70b-versatile"; // Default if Groq
            let isGroq = !!process.env.GROQ_API_KEY;

            try {
                let textConfig = { apiKey: process.env.GROQ_API_KEY };
                let Groq;

                if (isGroq) {
                    Groq = require("groq-sdk");
                } else {
                    // Fallback to Gemini if no Groq key
                    isGroq = false;
                }

                // FETCH PAGE CONTEXT
                let pageContext = "";
                try {
                    const controller = new AbortController();
                    const timeoutId = setTimeout(() => controller.abort(), 5000); // 5s timeout

                    const fetchRes = await fetch(url, { signal: controller.signal });
                    const html = await fetchRes.text();
                    clearTimeout(timeoutId);

                    // Extract Title
                    const titleMatch = html.match(/<title>(.*?)<\/title>/i);
                    const title = titleMatch ? titleMatch[1] : "No Title";

                    // Extract Meta Description
                    const metaMatch = html.match(/<meta\s+name=["']description["']\s+content=["'](.*?)["']/i);
                    const description = metaMatch ? metaMatch[1] : "No Description";

                    pageContext = `Page Title: "${title}"\nMeta Description: "${description}"`;
                    console.log(`[AI-Verify] Fetched Context: ${pageContext}`);
                } catch (e) {
                    pageContext = "Could not fetch page content (Host unreachable or blocking bots). Analyze URL pattern only.";
                    console.warn(`[AI-Verify] Fetch failed: ${e.message}`);
                }

                if (isGroq) {
                    const groq = new Groq(textConfig);
                    const completion = await groq.chat.completions.create({
                        messages: [
                            { role: "system", content: "You are PhishingShield AI. Analyze the URL and Page Context.\nTask: Classify the site into one of 3 categories:\n1. 'SAFE' (Legitimate sites like Instagram, Google, Gamma).\n2. 'SUSPICIOUS' (Unknown, shortened, or typos).\n3. 'MALICIOUS' (Phishing, scam, fake login).\nReturn JSON: {classification: 'SAFE'|'SUSPICIOUS'|'MALICIOUS', reason: 'Short explanation'}." },
                            { role: "user", content: `URL: ${url}\nContext: ${pageContext}` }
                        ],
                        model: modelName,
                        temperature: 0.1,
                        response_format: { type: "json_object" }
                    });
                    const result = JSON.parse(completion.choices[0]?.message?.content || "{}");

                    // Manual Mapping to Risk Score to prevent Hallucinations
                    const cls = (result.classification || "SUSPICIOUS").toUpperCase();
                    if (cls === "SAFE") aiScore = 0;
                    else if (cls === "MALICIOUS") aiScore = 95;
                    else aiScore = 45; // SUSPICIOUS

                    aiSuggestion = (aiScore > 70) ? "BAN" : (aiScore > 30 ? "CAUTION" : "IGNORE");
                    aiReason = result.reason;
                    console.log("[AI-Verify] Groq Success:", result, "mapped to", aiScore);
                } else {
                    // GEMINI LEGACY LOGIC
                    const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
                    const model = genAI.getGenerativeModel({ model: "gemini-flash-latest" });
                    const prompt = `Analyze URL ${url} for phishing. Return JSON {score, suggestion, reason}`;
                    const result = await model.generateContent(prompt);
                    const json = JSON.parse(result.response.text().replace(/```json/g, '').replace(/```/g, ''));
                    aiScore = json.score;
                    aiSuggestion = json.suggestion;
                    aiReason = json.reason;
                    console.log("[AI-Verify] Gemini Success:", json);
                }
            } catch (err) {
                console.error("[AI-Verify] AI Failed:", err.message);
                aiReason = "AI Service Unavailable";
            }
        } else {
            // NO API KEY - Use Heuristics
            console.log("[AI-Verify] No API Key found. Using Heuristics.");
            aiReason = "[Heuristic] No suspicious keywords or IP patterns found.";

            const suspiciousKeywords = [
                "login",
                "signin",
                "secure",
                "account",
                "update",
                "verify",
                "wallet",
                "bank",
                "crypto",
            ];

            let riskCount = 0;
            suspiciousKeywords.forEach((word) => {
                if (url.includes(word)) riskCount++;
            });

            // Check for IP address usage (simple regex)
            if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
                riskCount += 2;
            }

            if (riskCount >= 2) {
                aiScore = 85;
                aiSuggestion = "BAN";
                aiReason = "Multiple high-risk keywords detected (Phishing Indicators).";
            } else if (riskCount === 1) {
                aiScore = 45;
                aiSuggestion = "CAUTION";
                aiReason = "Contains sensitive keywords, requires manual review.";
            }
        }
        // Update Report with AI Data -- END of IF/ELSE Block
        reports[reportIndex] = {
            ...report,
            aiAnalysis: {
                score: aiScore,
                suggestion: aiSuggestion,
                reason: aiReason,
                timestamp: Date.now(),
            },
        };

        // FIX: Save using writeData
        writeData(REPORTS_FILE, reports);

        console.log(`[AI-Verify] Analyzed ${url} -> ${aiSuggestion} (${aiScore})`);
        res.json({ success: true, aiAnalysis: reports[reportIndex].aiAnalysis });
    } catch (error) {
        console.error("[AI-Verify] Error:", error);
        res.status(500).json({ success: false, error: "Internal Server Error during AI Analysis" });
    }
});

// MIDDLEWARE: Check Admin Access
const requireAdmin = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    if (!authHeader)
        return res.status(401).json({ success: false, message: "Token required" });

    const token = authHeader.split(" ")[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        // Verify it's an admin token
        if (decoded.role !== "admin" || !decoded.mfaVerified) {
            return res
                .status(403)
                .json({ success: false, message: "Admin access required" });
        }

        // Verify session exists in PERSISTENT store
        const sessionId = decoded.sessionId;
        const sessions = getAdminSessions(); // Read from file

        if (!sessions[sessionId]) {
            return res
                .status(401)
                .json({ success: false, message: "Session expired" });
        }

        // Check session expiry
        const session = sessions[sessionId];
        if (Date.now() > session.expiresAt) {
            delete sessions[sessionId];
            saveAdminSessions(sessions);
            return res
                .status(401)
                .json({ success: false, message: "Session expired" });
        }

        req.admin = decoded;
        req.sessionId = sessionId;
        next();
    } catch (error) {
        if (error.name === "TokenExpiredError") {
            return res.status(401).json({ success: false, message: "Token expired" });
        }
        return res.status(401).json({ success: false, message: "Invalid token" });
    }
};

// GET /api/auth/admin/verify - Verify admin token validity
app.get("/api/auth/admin/verify", requireAdmin, (req, res) => {
    res.json({
        success: true,
        admin: {
            email: req.admin.email,
            role: req.admin.role,
        },
    });
});

// GET /api/admin/logs - Get audit logs (Admin Only)
app.get("/api/admin/logs", requireAdmin, (req, res) => {
    const logs = readData(AUDIT_LOG_FILE);
    // Return last 100 logs
    const recentLogs = logs.slice(-100).reverse();
    res.json({ success: true, logs: recentLogs });
});

// --- REPORTS API ---

// (Duplicate Routes Removed)

// POST /api/reports/update - Update report status (ban/ignore/pending)
app.post("/api/reports/update", (req, res) => {
    const { id, status } = req.body; // status: 'banned', 'ignored', 'pending'
    if (!id || !status)
        return res
            .status(400)
            .json({ success: false, message: "ID and status required" });

    const reports = readData(REPORTS_FILE) || [];
    const idx = reports.findIndex((r) => r.id === id);

    if (idx !== -1) {
        reports[idx].status = status;
        if (status === "banned") reports[idx].bannedAt = Date.now();
        if (status === "ignored") reports[idx].ignoredAt = Date.now();

        writeData(REPORTS_FILE, reports);
        console.log(`[Report] Updated status for ${id} to ${status}`);
        res.json({ success: true });
    } else {
        res.status(404).json({ success: false, message: "Report not found" });
    }
});

// Start Server
// Bind to 0.0.0.0 to accept connections from Render's network
app.listen(PORT, "0.0.0.0", () => {
    console.log(`PhishingShield Backend running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || "development"}`);
});
