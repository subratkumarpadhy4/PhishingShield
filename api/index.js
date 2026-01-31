// Vercel Serverless API - PhishingShield Backend
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

// Environment variables from Vercel
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/phishingshield';
const JWT_SECRET = process.env.JWT_SECRET || 'phishingshield-secret-key';

// MongoDB connection state
let isConnected = false;

// Connect to MongoDB
async function connectDB() {
    if (isConnected) return;
    if (mongoose.connection.readyState === 1) {
        isConnected = true;
        return;
    }

    try {
        await mongoose.connect(MONGODB_URI, {
            serverSelectionTimeoutMS: 5000,
        });
        isConnected = true;
        console.log('[MongoDB] Connected');
    } catch (error) {
        console.error('[MongoDB] Connection failed:', error.message);
        throw error;
    }
}

// Mongoose Schemas
const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String },
    name: { type: String },
    xp: { type: Number, default: 0 },
    level: { type: Number, default: 1 },
    safeStreak: { type: Number, default: 0 },
    lastUpdated: { type: Number, default: Date.now }
}, { timestamps: true });

const ReportSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true },
    url: { type: String, required: true },
    hostname: { type: String, required: true },
    reporter: { type: String },
    reporterEmail: { type: String },
    timestamp: { type: Number, required: true },
    status: { type: String, default: 'pending' }
}, { timestamps: true });

const TrustScoreSchema = new mongoose.Schema({
    domain: { type: String, required: true, unique: true, lowercase: true, trim: true },
    safe: { type: Number, default: 0 },
    unsafe: { type: Number, default: 0 },
    voters: { type: mongoose.Schema.Types.Mixed, default: {} }
}, { timestamps: true });

// Models
const User = mongoose.models.User || mongoose.model('User', UserSchema);
const Report = mongoose.models.Report || mongoose.model('Report', ReportSchema);
const TrustScore = mongoose.models.TrustScore || mongoose.model('TrustScore', TrustScoreSchema);

// Middleware
app.use(cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
}));
app.options("*", cors());
app.use(bodyParser.json());

// Root endpoint
app.get("/api", (req, res) => {
    res.json({ status: "ok", message: "PhishingShield API Running on Vercel" });
});

// Health check
app.get("/api/health", async (req, res) => {
    try {
        await connectDB();
        res.json({ status: "healthy", mongodb: isConnected });
    } catch (error) {
        res.status(500).json({ status: "unhealthy", error: error.message });
    }
});

// Reports endpoints
app.get("/api/reports", async (req, res) => {
    try {
        await connectDB();
        const reports = await Report.find({}).lean();
        res.json(reports.map(r => ({ ...r, _id: undefined, __v: undefined })));
    } catch (error) {
        console.error('[API] Reports error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post("/api/reports", async (req, res) => {
    try {
        await connectDB();
        const report = new Report(req.body);
        await report.save();
        res.json({ success: true, report });
    } catch (error) {
        console.error('[API] Report creation error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Users endpoints
app.get("/api/users", async (req, res) => {
    try {
        await connectDB();
        const users = await User.find({}).lean();
        res.json(users.map(u => ({ ...u, _id: undefined, __v: undefined, password: undefined })));
    } catch (error) {
        console.error('[API] Users error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post("/api/users/create", async (req, res) => {
    try {
        await connectDB();
        const { email, password, name } = req.body;

        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) {
            return res.status(400).json({ success: false, message: "User already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            email: email.toLowerCase(),
            password: hashedPassword,
            name,
            xp: 0,
            level: 1
        });
        await user.save();

        res.json({ success: true, message: "User created" });
    } catch (error) {
        console.error('[API] User creation error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post("/api/users/login", async (req, res) => {
    try {
        await connectDB();
        const { email, password } = req.body;

        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(401).json({ success: false, message: "Invalid credentials" });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ success: false, message: "Invalid credentials" });
        }

        const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '30d' });

        res.json({
            success: true,
            user: {
                email: user.email,
                name: user.name,
                xp: user.xp,
                level: user.level
            },
            token
        });
    } catch (error) {
        console.error('[API] Login error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post("/api/users/sync", async (req, res) => {
    try {
        await connectDB();
        const { email, xp, level } = req.body;

        const user = await User.findOneAndUpdate(
            { email: email.toLowerCase() },
            { xp, level, lastUpdated: Date.now() },
            { new: true }
        );

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        res.json({ success: true, user: { email: user.email, xp: user.xp, level: user.level } });
    } catch (error) {
        console.error('[API] Sync error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Trust Score endpoints
app.get("/api/trust/score", async (req, res) => {
    try {
        await connectDB();
        const { domain } = req.query;
        if (!domain) return res.status(400).json({ error: "Domain required" });

        const score = await TrustScore.findOne({ domain: domain.toLowerCase() });

        if (!score) {
            return res.json({ score: null, votes: 0, safe: 0, unsafe: 0, status: 'unknown' });
        }

        const total = score.safe + score.unsafe;
        const trustScore = total === 0 ? null : Math.round((score.safe / total) * 100);

        res.json({
            score: trustScore,
            votes: total,
            safe: score.safe,
            unsafe: score.unsafe,
            status: trustScore === null ? 'unknown' : (trustScore > 70 ? 'safe' : (trustScore < 30 ? 'malicious' : 'suspect'))
        });
    } catch (error) {
        console.error('[API] Trust score error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post("/api/trust/vote", async (req, res) => {
    try {
        await connectDB();
        const { domain, vote, userId } = req.body;
        if (!domain || !vote) return res.status(400).json({ error: "Domain and vote required" });

        const normalizedDomain = domain.toLowerCase().trim();

        let trustScore = await TrustScore.findOne({ domain: normalizedDomain });

        if (!trustScore) {
            trustScore = new TrustScore({
                domain: normalizedDomain,
                safe: vote === 'safe' ? 1 : 0,
                unsafe: vote === 'unsafe' ? 1 : 0,
                voters: userId ? { [userId]: vote } : {}
            });
        } else {
            if (vote === 'safe') trustScore.safe++;
            else if (vote === 'unsafe') trustScore.unsafe++;

            if (userId) {
                trustScore.voters = { ...trustScore.voters, [userId]: vote };
            }
        }

        await trustScore.save();

        res.json({ success: true, message: "Vote recorded" });
    } catch (error) {
        console.error('[API] Vote error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get("/api/trust/all", async (req, res) => {
    try {
        await connectDB();
        const scores = await TrustScore.find({}).lean();
        res.json(scores.map(s => ({
            domain: s.domain,
            safe: s.safe,
            unsafe: s.unsafe,
            voters: s.voters
        })));
    } catch (error) {
        console.error('[API] Trust all error:', error);
        res.status(500).json({ error: error.message });
    }
});

// OTP endpoints (simplified - email sending would need EmailJS integration)
app.post("/api/send-otp", async (req, res) => {
    try {
        await connectDB();
        const { email } = req.body;

        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        // Generate OTP (in production, send via email)
        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        // Store OTP temporarily (simplified - in production use redis/db)
        user.otp = otp;
        user.otpExpiry = Date.now() + 10 * 60 * 1000; // 10 minutes
        await user.save();

        console.log(`[OTP] Generated for ${email}: ${otp}`);

        res.json({ success: true, message: "OTP sent (check logs for demo)" });
    } catch (error) {
        console.error('[API] OTP error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Leaderboard
app.get("/api/leaderboard", async (req, res) => {
    try {
        await connectDB();
        const users = await User.find({})
            .select('email name xp level -_id')
            .sort({ xp: -1 })
            .limit(100)
            .lean();

        res.json(users);
    } catch (error) {
        console.error('[API] Leaderboard error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Export for Vercel
module.exports = app;
