const API_URL = "https://oculus-eight.vercel.app"; // Production URL

const chatBox = document.getElementById('chat-box');
const userInput = document.getElementById('user-input');
const typing = document.getElementById('typing-indicator');
const sendBtn = document.getElementById('send-btn');
const playAgainBtn = document.getElementById('play-again-btn');
const tryAgainFailBtn = document.getElementById('try-again-fail-btn');
const startBtn = document.getElementById('start-sim-btn');
const loadingText = document.getElementById('loading-text');

let history = [];
let currentSystemPrompt = "";

// START SIMULATION
if (startBtn) {
    startBtn.addEventListener('click', async () => {
        startBtn.style.display = 'none';
        loadingText.style.display = 'block';

        try {
            // Request new scenario from AI
            const res = await fetch(`${API_URL}/api/ai/chat/start`, { method: 'POST' });
            const data = await res.json();

            if (data.success) {
                // Apply Scenario
                document.querySelector('.status').textContent = `LIVE SCENARIO: ${data.scenario_title}`;
                currentSystemPrompt = data.system_instruction;

                // Hide Overlay
                document.getElementById('start-overlay').style.display = 'none';

                // Initial Message
                addMessage("bot", data.opening_line);
            } else {
                alert("Failed to generate scenario. Try again.");
                loadingText.style.display = 'none';
                startBtn.style.display = 'block';
            }
        } catch (e) {
            console.error(e);
            alert("Connection Error. Is the backend running?");
            loadingText.style.display = 'none';
            startBtn.style.display = 'block';
        }
    });
}

// Event Listeners
if (userInput) {
    userInput.addEventListener("keypress", function (event) {
        if (event.key === "Enter") {
            sendMessage();
        }
    });
}

if (sendBtn) sendBtn.addEventListener("click", sendMessage);
if (playAgainBtn) playAgainBtn.addEventListener("click", () => location.reload());
if (tryAgainFailBtn) tryAgainFailBtn.addEventListener("click", () => location.reload());

function addMessage(sender, text) {
    const div = document.createElement('div');
    div.classList.add('message', sender);
    div.innerHTML = text;
    chatBox.appendChild(div);
    chatBox.scrollTop = chatBox.scrollHeight;
}

async function sendMessage() {
    const text = userInput.value.trim();
    if (!text) return;

    addMessage("user", text);
    userInput.value = "";
    history.push({ role: "user", content: text });

    if (typing) typing.style.display = "block";

    try {
        // Call API
        const response = await fetch(`${API_URL}/api/ai/chat`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                message: text,
                history: history,
                systemPrompt: currentSystemPrompt // Send strict context
            })
        });

        const data = await response.json();
        if (typing) typing.style.display = "none";

        if (data.reply) {
            addMessage("bot", data.reply);
            history.push({ role: "assistant", content: data.reply });

            // Check for Win Condition
            if (data.reply.includes("TRAINING COMPLETE") || data.reply.includes("caught me")) {
                setTimeout(() => {
                    const overlay = document.getElementById('win-overlay');
                    if (overlay) overlay.style.display = 'flex';
                }, 1000);
            }
            // Check for Fail Condition
            else if (data.reply.includes("SIMULATION FAILED") || data.reply.includes("SCAMMED")) {
                setTimeout(() => {
                    const overlay = document.getElementById('fail-overlay');
                    if (overlay) overlay.style.display = 'flex';
                }, 1000);
            }

        } else {
            addMessage("bot", "[Connection Error] The scammer disconnected.");
        }

    } catch (error) {
        if (typing) typing.style.display = "none";
        addMessage("bot", "Error connecting to AI Server.");
        console.error(error);
    }
}

// --- TABS & MODES LOGIC ---
const navChat = document.getElementById('nav-chat');
const navTraining = document.getElementById('nav-training');
const navDomain = document.getElementById('nav-domain');

const chatContainer = document.getElementById('chat-tab-container');
const trainingArea = document.getElementById('training-dojo');
const domainArea = document.getElementById('domain-dojo');

const domainInput = document.getElementById('domain-input');
const analyzeBtn = document.getElementById('analyze-btn');

function switchTab(tab) {
    // Reset all nav buttons (remove active class and inline overrides)
    [navChat, navTraining, navDomain].forEach(btn => {
        if (btn) {
            btn.classList.remove('active');
            btn.style.background = '';
            btn.style.color = '';
            btn.style.boxShadow = '';
        }
    });

    // Hide all content areas
    [chatContainer, trainingArea, domainArea].forEach(el => {
        if (el) el.style.display = 'none';
    });

    // Activate specific tab
    if (tab === 'chat') {
        if (navChat) navChat.classList.add('active');
        if (chatContainer) chatContainer.style.display = 'flex';
    }
    else if (tab === 'training') {
        if (navTraining) navTraining.classList.add('active');
        if (trainingArea) {
            trainingArea.style.display = 'flex';
            if (typeof initTraining === 'function') initTraining();
        }
    }
    else if (tab === 'domain') {
        if (navDomain) navDomain.classList.add('active');
        if (domainArea) domainArea.style.display = 'block';
    }

    // Overlay Handling
    const startOverlay = document.getElementById('start-overlay');
    if (tab !== 'chat') {
        if (startOverlay) startOverlay.style.display = 'none';
    }
}

// Event Listeners for Tabs
if (navChat) navChat.addEventListener('click', () => switchTab('chat'));
if (navTraining) navTraining.addEventListener('click', () => switchTab('training'));
if (navDomain) navDomain.addEventListener('click', () => switchTab('domain'));

// Domain Analysis
if (analyzeBtn) {
    analyzeBtn.addEventListener('click', async () => {
        const url = domainInput.value.trim();
        if (!url) return;

        // Show Loading
        document.getElementById('ai-analysis-text').textContent = "Running heuristic & AI scan...";
        document.getElementById('domain-result').style.display = 'block';

        // 1. Calculate Entropy
        const entropy = calculateEntropy(url);
        document.getElementById('entropy-score').textContent = entropy.toFixed(2);

        // 2. Check Typosquatting
        const typos = checkTyposquat(url);
        const typoEl = document.getElementById('typo-detected');
        if (typos) {
            typoEl.textContent = "YES";
            typoEl.style.color = "#ef4444";
        } else {
            typoEl.textContent = "No";
            typoEl.style.color = "#4ade80";
        }

        // 3. AI Analysis
        try {
            const prompt = `Analyze this URL for phishing risk: "${url}". Be technical. Mention if it looks like a fake login or safe. Keep it under 30 words.`;

            const response = await fetch(`${API_URL}/api/ai/chat`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: prompt,
                    history: [],
                    systemPrompt: "You are a Cyber Forensic Analyst. Analyze the URLs provided. Be concise."
                })
            });
            const data = await response.json();
            if (data.reply) {
                document.getElementById('ai-analysis-text').textContent = data.reply;
            }
        } catch (e) {
            document.getElementById('ai-analysis-text').textContent = "AI Analysis Failed (Offline).";
        }
    });
}

function calculateEntropy(str) {
    const len = str.length;
    const frequencies = {};
    for (let i = 0; i < len; i++) {
        const char = str[i];
        frequencies[char] = (frequencies[char] || 0) + 1;
    }
    let entropy = 0;
    for (const char in frequencies) {
        const p = frequencies[char] / len;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

function checkTyposquat(url) {
    const targets = ['google', 'amazon', 'facebook', 'twitter', 'apple', 'microsoft'];
    const clean = url.replace(/https?:\/\//, '').replace('www.', '');

    for (let t of targets) {
        if (clean.includes(t) && !clean.startsWith(t + '.')) return true;
    }
    return false;
}

// --- SPOT THE PHISH GAME LOGIC (Imported from Dojo Module) ---

// Question Bank: A mix of obvious and subtle phishing scenarios
const trainingCases = [
    // --- LEVEL 1: Legitimate Domains ---
    { id: 1, difficulty: 1, scenario: "Google Search.", url: "https://www.google.com", isPhish: false, reason: "Safe. Official Google domain." },
    { id: 2, difficulty: 1, scenario: "Amazon Shopping.", url: "https://www.amazon.com", isPhish: false, reason: "Safe. Official Amazon domain." },
    { id: 3, difficulty: 1, scenario: "Facebook Login.", url: "https://www.facebook.com", isPhish: false, reason: "Safe. Official Facebook domain." },
    { id: 4, difficulty: 1, scenario: "Netflix Home.", url: "https://www.netflix.com", isPhish: false, reason: "Safe. Official Netflix domain." },
    { id: 5, difficulty: 1, scenario: "LinkedIn Profile.", url: "https://www.linkedin.com/in/me", isPhish: false, reason: "Safe. Official LinkedIn domain." },
    { id: 6, difficulty: 1, scenario: "PayPal Dashboard.", url: "https://www.paypal.com/myaccount", isPhish: false, reason: "Safe. Official PayPal domain." },
    { id: 7, difficulty: 1, scenario: "Microsoft Office.", url: "https://www.office.com", isPhish: false, reason: "Safe. Official Microsoft domain." },
    { id: 8, difficulty: 1, scenario: "Zoom Meeting.", url: "https://zoom.us/j/123456", isPhish: false, reason: "Safe. Zoom uses `.us` TLD." },
    { id: 9, difficulty: 2, scenario: "Apple ID Management.", url: "https://appleid.apple.com", isPhish: false, reason: "Safe. `appleid` is a subdomain of `apple.com`." },
    { id: 10, difficulty: 2, scenario: "Bank of America.", url: "https://www.bankofamerica.com", isPhish: false, reason: "Safe. Official domain." },

    // --- LEVEL 2: Basic Typosquatting ---
    { id: 11, difficulty: 1, scenario: "Facebook Friend Request.", url: "https://faceb0ok.com", isPhish: true, reason: "Phishing. Zero '0' used instead of 'o'." },
    { id: 12, difficulty: 1, scenario: "Google Docs.", url: "https://gooogle.com/docs", isPhish: true, reason: "Phishing. Extra 'o' in Google." },
    { id: 13, difficulty: 1, scenario: "Twitter DM.", url: "https://twitterr.com", isPhish: true, reason: "Phishing. Double 'r' at the end." },
    { id: 14, difficulty: 1, scenario: "Amazon Order.", url: "https://amazonn.com", isPhish: true, reason: "Phishing. Double 'n' at the end." },
    { id: 15, difficulty: 1, scenario: "Instagram Photo.", url: "https://instgram.com", isPhish: true, reason: "Phishing. Missing 'a' (Inst-gram)." },
    { id: 16, difficulty: 1, scenario: "LinkedIn Job Alert.", url: "https://link-edin.com", isPhish: true, reason: "Phishing. Added hyphen inside the brand name." },
    { id: 17, difficulty: 1, scenario: "Microsoft Login.", url: "https://micosoft.com", isPhish: true, reason: "Phishing. Missing 'r' in Microsoft." },
    { id: 18, difficulty: 1, scenario: "Netflix Update.", url: "https://net-flix.com", isPhish: true, reason: "Phishing. Added hyphen." },
    { id: 19, difficulty: 1, scenario: "WhatsApp Web.", url: "https://whatsap.com", isPhish: true, reason: "Phishing. Single 'p' instead of double." },
    { id: 20, difficulty: 1, scenario: "YouTube Video.", url: "https://yuotube.com", isPhish: true, reason: "Phishing. Swapped 'u' and 'o'." },

    // --- LEVEL 3: TLD & Extension Spoofing ---
    { id: 21, difficulty: 2, scenario: "Amazon Deals.", url: "http://amazon-orders.net", isPhish: true, reason: "Phishing. Amazon uses `.com`, rarely `.net` for orders." },
    { id: 22, difficulty: 2, scenario: "Google Support.", url: "https://google-help.xyz", isPhish: true, reason: "Phishing. `.xyz` is common for spam. Google uses `google.com`." },
    { id: 23, difficulty: 2, scenario: "Netflix Billing.", url: "http://netflix.billing-update.info", isPhish: true, reason: "Phishing. The domain is `billing-update.info`." },
    { id: 24, difficulty: 2, scenario: "Office 365 Login.", url: "http://office365-login.org", isPhish: true, reason: "Phishing. Microsoft doesn't use `.org` for login portals." },
    { id: 25, difficulty: 2, scenario: "PayPal Secure.", url: "https://paypal-secure.biz", isPhish: true, reason: "Phishing. `.biz` is unprofessional." },
    { id: 26, difficulty: 2, scenario: "Apple Store.", url: "http://apple-store.shop", isPhish: true, reason: "Phishing. Apple uses `apple.com`." },
    { id: 27, difficulty: 2, scenario: "Chase Bank.", url: "https://chase-bank.online", isPhish: true, reason: "Phishing. Major banks rarely use generic TLDs like `.online`." },
    { id: 28, difficulty: 2, scenario: "Zoom Invite.", url: "https://zoom-meetings.club", isPhish: true, reason: "Phishing. Zoom uses `zoom.us`." },
    { id: 29, difficulty: 2, scenario: "Slack Login.", url: "https://slack-workspace.site", isPhish: true, reason: "Phishing. Slack uses `slack.com`." },
    { id: 30, difficulty: 2, scenario: "Dropbox Share.", url: "https://dropbox-files.top", isPhish: true, reason: "Phishing. `.top` is a high-risk TLD." },

    // --- LEVEL 4: Subdomain Chaining ---
    { id: 31, difficulty: 2, scenario: "Apple ID Reset.", url: "http://apple.id.security-check.com", isPhish: true, reason: "Phishing. Real domain is `security-check.com`." },
    { id: 32, difficulty: 2, scenario: "PayPal Verification.", url: "https://paypal.com.secure-account.net", isPhish: true, reason: "Phishing. Real domain is `secure-account.net`." },
    { id: 33, difficulty: 2, scenario: "Google Drive.", url: "https://drive.google.com.files.sharing.io", isPhish: true, reason: "Phishing. Real domain is `sharing.io`." },
    { id: 34, difficulty: 2, scenario: "Amazon Prime.", url: "http://amazon.com-prime.rewards.club", isPhish: true, reason: "Phishing. Real domain is `rewards.club`." },
    { id: 35, difficulty: 2, scenario: "Facebook Login.", url: "https://login.facebook.com.account-recovery.yz", isPhish: true, reason: "Phishing. Real domain is `account-recovery.yz`." },
    { id: 36, difficulty: 2, scenario: "Bank Alert.", url: "https://chase.com.verify.login.alerts.net", isPhish: true, reason: "Phishing. Real domain is `alerts.net`." },
    { id: 37, difficulty: 2, scenario: "Microsoft Teams.", url: "https://teams.microsoft.com.meeting-join.net", isPhish: true, reason: "Phishing. Real domain is `meeting-join.net`." },
    { id: 38, difficulty: 2, scenario: "Netflix Free Month.", url: "http://netflix.com.free-offer.site", isPhish: true, reason: "Phishing. Real domain is `free-offer.site`." },
    { id: 39, difficulty: 2, scenario: "Internal HR.", url: "https://hr.google.com", isPhish: false, reason: "Safe. `hr` is a subdomain of `google.com`." },
    { id: 40, difficulty: 2, scenario: "Dev Portal.", url: "https://developer.apple.com", isPhish: false, reason: "Safe. `developer` is a subdomain of `apple.com`." },

    // --- LEVEL 5: Homograph Attacks ---
    { id: 41, difficulty: 3, scenario: "Coinbase Login.", url: "https://www.coịnbasẹ.com", isPhish: true, reason: "Phishing. Dots under 'i' and 'e' (Vietnamese characters)." },
    { id: 42, difficulty: 3, scenario: "Apple Support.", url: "https://www.appIe.com", isPhish: true, reason: "Phishing. Capital 'I' (Eye) used instead of 'l' (El)." },
    { id: 43, difficulty: 3, scenario: "Google Login.", url: "https://www.googIe.com", isPhish: true, reason: "Phishing. Capital 'I' (Eye) instead of 'l' (El)." },
    { id: 44, difficulty: 3, scenario: "PayPal Secure.", url: "https://www.paypaI.com", isPhish: true, reason: "Phishing. Capital 'I' (Eye) instead of 'l' (El)." },
    { id: 45, difficulty: 3, scenario: "Amazon Shopping.", url: "https://www.arnazon.com", isPhish: true, reason: "Phishing. 'r' + 'n' looks like 'm'." },
    { id: 46, difficulty: 3, scenario: "Microsoft.", url: "https://www.rnicrosoft.com", isPhish: true, reason: "Phishing. 'r' + 'n' looks like 'm'." },
    { id: 47, difficulty: 3, scenario: "Epic Games.", url: "https://www.epicgarnes.com", isPhish: true, reason: "Phishing. 'r' + 'n' looks like 'm'." },
    { id: 48, difficulty: 3, scenario: "Instagram.", url: "https://www.instagram.co", isPhish: true, reason: "Phishing. Missing 'm' at the end (.co instead of .com)." },
    { id: 49, difficulty: 3, scenario: "Generic Bank.", url: "https://www.bạṅk.com", isPhish: true, reason: "Phishing. Accents on letters." },
    { id: 50, difficulty: 3, scenario: "Russian VK.", url: "https://vk.com", isPhish: false, reason: "Safe. Valid short domain." },

    // --- LEVEL 6: Hyphenated Confusion ---
    { id: 51, difficulty: 1, scenario: "Secure Login.", url: "http://paypal-secure-login.com", isPhish: true, reason: "Phishing. Attackers imply it's PayPal via hyphens." },
    { id: 52, difficulty: 1, scenario: "Amazon Prime.", url: "http://amazon-prime-video.net", isPhish: true, reason: "Phishing. Long hyphenated domain." },
    { id: 53, difficulty: 1, scenario: "Google Cloud.", url: "https://google-cloud-storage.com", isPhish: true, reason: "Phishing. Real domain is `cloud.google.com`." },
    { id: 54, difficulty: 1, scenario: "Apple Support.", url: "https://apple-support-center.com", isPhish: true, reason: "Phishing. Real domain is `support.apple.com`." },
    { id: 55, difficulty: 1, scenario: "Facebook Security.", url: "https://facebook-security-check.com", isPhish: true, reason: "Phishing. Real domain is `facebook.com`." },
    { id: 56, difficulty: 1, scenario: "Netflix Account.", url: "https://netflix-account-update.com", isPhish: true, reason: "Phishing. Real domain is `netflix.com`." },
    { id: 57, difficulty: 1, scenario: "Instagram Verify.", url: "https://instagram-verify-badge.com", isPhish: true, reason: "Phishing. Real domain is `instagram.com`." },
    { id: 58, difficulty: 1, scenario: "WhatsApp Backup.", url: "https://whatsapp-backup-restore.com", isPhish: true, reason: "Phishing. Real domain is `whatsapp.com`." },
    { id: 59, difficulty: 1, scenario: "Twitter Support.", url: "https://twitter-helpdesk.com", isPhish: true, reason: "Phishing. Real domain is `help.twitter.com`." },
    { id: 60, difficulty: 1, scenario: "LinkedIn Jobs.", url: "https://linkedin-jobs-apply.com", isPhish: true, reason: "Phishing. Real domain is `linkedin.com`." },

    // --- LEVEL 7: Brand Abuse ---
    { id: 61, difficulty: 2, scenario: "Windows Virus Alert.", url: "http://microsoft-windows-support.com", isPhish: true, reason: "Phishing. Microsoft doesn't use `microsoft-windows-support.com`." },
    { id: 62, difficulty: 2, scenario: "McAfee Expiry.", url: "https://mcafee-renewal-discount.com", isPhish: true, reason: "Phishing. Fake renewal site." },
    { id: 63, difficulty: 2, scenario: "Norton Antivirus.", url: "http://norton-antivirus-check.com", isPhish: true, reason: "Phishing. Fake checker site." },
    { id: 64, difficulty: 2, scenario: "Geek Squad Help.", url: "https://geek-squad-remote-help.com", isPhish: true, reason: "Phishing. Fake support site." },
    { id: 66, difficulty: 2, scenario: "Zoom Installer.", url: "https://zoom-download-center.com", isPhish: true, reason: "Phishing. Real domain is `zoom.us/download`." },
    { id: 67, difficulty: 2, scenario: "Chrome Update.", url: "http://chrome-update-browser.com", isPhish: true, reason: "Phishing. Chrome updates automatically internally." },
    { id: 68, difficulty: 2, scenario: "Driver Update.", url: "https://hp-drivers-update.com", isPhish: true, reason: "Phishing. Real domain is `support.hp.com`." },
    { id: 69, difficulty: 2, scenario: "Dell Support.", url: "https://dell-laptop-support.com", isPhish: true, reason: "Phishing. Real domain is `dell.com`." },
    { id: 70, difficulty: 2, scenario: "Lenovo Drivers.", url: "http://lenovo-drivers-fix.com", isPhish: true, reason: "Phishing. Real domain is `lenovo.com`." },

    // --- LEVEL 8: File Vectors ---
    { id: 71, difficulty: 2, scenario: "PDF Invoice.", url: "data:text/html;base64,PHNjcmlwdD5hbGVydCgnaGFja2VkJyk8L3NjcmlwdD4=", isPhish: true, reason: "Phishing. Data URI contains executable code." },
    { id: 72, difficulty: 2, scenario: "Local File.", url: "file:///C:/Users/Admin/Downloads/invoice.exe", isPhish: true, reason: "Phishing. Links to local file execution." },

    // --- LEVEL 9: URL Shorteners & Obfuscation ---
    { id: 76, difficulty: 3, scenario: "Bitly Link.", url: "https://bit.ly/3x89a", isPhish: true, reason: "Phishing. Short links hide the destination." },
    { id: 77, difficulty: 3, scenario: "TinyURL.", url: "https://tinyurl.com/secure-login", isPhish: true, reason: "Phishing. Short links hide the destination." },
    { id: 79, difficulty: 3, scenario: "Username Obfuscation.", url: "https://google.com@evil.com", isPhish: true, reason: "Phishing. `@` symbol makes `google.com` the username." },
    { id: 80, difficulty: 3, scenario: "IP Address.", url: "http://45.33.22.11/login", isPhish: true, reason: "Phishing. Professional sites use domains, not IPs." },
    { id: 81, difficulty: 3, scenario: "Local Router.", url: "http://192.168.1.1", isPhish: false, reason: "Safe. Local router IP address." },
    { id: 82, difficulty: 3, scenario: "Localhost.", url: "http://127.0.0.1:3000", isPhish: false, reason: "Safe. Local development server." },
    { id: 83, difficulty: 3, scenario: "Discord Gift.", url: "https://dlscord.gg/gift", isPhish: true, reason: "Phishing. `dlscord` (L) instead of `discord`." },

    // --- LEVEL 10: Final Exam ---
    { id: 86, difficulty: 2, scenario: "Fortnite V-Bucks.", url: "https://fortnite-vbucks-generator.net", isPhish: true, reason: "Phishing. Fake generator site." },
    { id: 87, difficulty: 2, scenario: "Minecraft Skins.", url: "https://minecraft.net", isPhish: false, reason: "Safe. Official domain." },
    { id: 88, difficulty: 2, scenario: "Twitch Stream.", url: "https://twitch.tv", isPhish: false, reason: "Safe. Official domain." },
    { id: 91, difficulty: 2, scenario: "Spotify Web Player.", url: "https://open.spotify.com", isPhish: false, reason: "Safe. Official subdomain." },
    { id: 92, difficulty: 2, scenario: "GitHub Repo.", url: "https://github.com", isPhish: false, reason: "Safe. Official domain." },
    { id: 93, difficulty: 2, scenario: "Fake GitHub.", url: "https://github-login.com", isPhish: true, reason: "Phishing. Fake login site." },
    { id: 94, difficulty: 1, scenario: "Wikipedia.", url: "https://wikipedia.org", isPhish: false, reason: "Safe. Official domain." },
    { id: 100, difficulty: 3, scenario: "The End.", url: "https://phishingshield.io", isPhish: false, reason: "Safe. That's us!" }
];

let currentQuiz = null;
let quizScore = 0;
let quizStreak = 0;

function initTraining() {
    if (!currentQuiz) nextQuiz();
}

function nextQuiz() {
    // Pick random case
    currentQuiz = trainingCases[Math.floor(Math.random() * trainingCases.length)];

    // Update UI
    document.getElementById('quiz-domain').textContent = currentQuiz.url;
    document.getElementById('quiz-domain').style.color = currentQuiz.isPhish ? "#fca5a5" : "#86efac"; // subtle hint color? No, keep it white for challenge.
    document.getElementById('quiz-domain').style.color = "white";

    // Hide Feedback
    document.getElementById('quiz-feedback').style.display = 'none';
}

function checkQuiz(userSaysSafe) {
    if (!currentQuiz) return;

    const isCorrect = (userSaysSafe && !currentQuiz.isPhish) || (!userSaysSafe && currentQuiz.isPhish);

    // Update Score
    if (isCorrect) {
        quizScore += 100;
        quizStreak++;
        document.getElementById('quiz-title').textContent = "CORRECT! 🎉";
        document.getElementById('quiz-title').style.color = "#4ade80";
        document.getElementById('quiz-icon').textContent = "🛡️";
    } else {
        quizStreak = 0;
        document.getElementById('quiz-title').textContent = "WRONG! 💀";
        document.getElementById('quiz-title').style.color = "#ef4444";
        document.getElementById('quiz-icon').textContent = "❌";
    }

    document.getElementById('quiz-score').textContent = quizScore;
    document.getElementById('quiz-streak').textContent = quizStreak;
    document.getElementById('quiz-reason').textContent = currentQuiz.reason;

    // Show Feedback
    document.getElementById('quiz-feedback').style.display = 'flex';
}

// Quiz Listeners
const btnSafe = document.getElementById('btn-safe');
const btnPhish = document.getElementById('btn-phish');
const btnNext = document.getElementById('btn-next-quiz');

if (btnSafe) btnSafe.addEventListener('click', () => checkQuiz(true));
if (btnPhish) btnPhish.addEventListener('click', () => checkQuiz(false));
if (btnNext) btnNext.addEventListener('click', nextQuiz);
