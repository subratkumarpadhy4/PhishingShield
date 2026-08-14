/**
 * Phishing Shield - Dojo Module
 * Handles the gamification and quiz logic.
 */

const Dojo = {
    currentQuestion: null,
    streak: 0, // Added streak tracking

    // Question Bank: A mix of obvious and subtle phishing scenarios
    questions: [
        // --- LEVEL 1: Legitimate Domains (The Control Group) ---
        { id: 1, difficulty: 1, scenario: "Google Search.", url: "https://www.google.com", isPhishing: false, explanation: "Safe. Official Google domain." },
        { id: 2, difficulty: 1, scenario: "Amazon Shopping.", url: "https://www.amazon.com", isPhishing: false, explanation: "Safe. Official Amazon domain." },
        { id: 3, difficulty: 1, scenario: "Facebook Login.", url: "https://www.facebook.com", isPhishing: false, explanation: "Safe. Official Facebook domain." },
        { id: 4, difficulty: 1, scenario: "Netflix Home.", url: "https://www.netflix.com", isPhishing: false, explanation: "Safe. Official Netflix domain." },
        { id: 5, difficulty: 1, scenario: "LinkedIn Profile.", url: "https://www.linkedin.com/in/me", isPhishing: false, explanation: "Safe. Official LinkedIn domain." },
        { id: 6, difficulty: 1, scenario: "PayPal Dashboard.", url: "https://www.paypal.com/myaccount", isPhishing: false, explanation: "Safe. Official PayPal domain." },
        { id: 7, difficulty: 1, scenario: "Microsoft Office.", url: "https://www.office.com", isPhishing: false, explanation: "Safe. Official Microsoft domain." },
        { id: 8, difficulty: 1, scenario: "Zoom Meeting.", url: "https://zoom.us/j/123456", isPhishing: false, explanation: "Safe. Zoom uses `.us` TLD." },
        { id: 9, difficulty: 2, scenario: "Apple ID Management.", url: "https://appleid.apple.com", isPhishing: false, explanation: "Safe. `appleid` is a subdomain of `apple.com`." },
        { id: 10, difficulty: 2, scenario: "Bank of America.", url: "https://www.bankofamerica.com", isPhishing: false, explanation: "Safe. Official domain." },

        // --- LEVEL 2: Basic Typosquatting (Visual Tricks) ---
        { id: 11, difficulty: 1, scenario: "Facebook Friend Request.", url: "https://faceb0ok.com", isPhishing: true, explanation: "Phishing. Zero '0' used instead of 'o'." },
        { id: 12, difficulty: 1, scenario: "Google Docs.", url: "https://gooogle.com/docs", isPhishing: true, explanation: "Phishing. Extra 'o' in Google." },
        { id: 13, difficulty: 1, scenario: "Twitter DM.", url: "https://twitterr.com", isPhishing: true, explanation: "Phishing. Double 'r' at the end." },
        { id: 14, difficulty: 1, scenario: "Amazon Order.", url: "https://amazonn.com", isPhishing: true, explanation: "Phishing. Double 'n' at the end." },
        { id: 15, difficulty: 1, scenario: "Instagram Photo.", url: "https://instgram.com", isPhishing: true, explanation: "Phishing. Missing 'a' (Inst-gram)." },
        { id: 16, difficulty: 1, scenario: "LinkedIn Job Alert.", url: "https://link-edin.com", isPhishing: true, explanation: "Phishing. Added hyphen inside the brand name." },
        { id: 17, difficulty: 1, scenario: "Microsoft Login.", url: "https://micosoft.com", isPhishing: true, explanation: "Phishing. Missing 'r' in Microsoft." },
        { id: 18, difficulty: 1, scenario: "Netflix Update.", url: "https://net-flix.com", isPhishing: true, explanation: "Phishing. Added hyphen." },
        { id: 19, difficulty: 1, scenario: "WhatsApp Web.", url: "https://whatsap.com", isPhishing: true, explanation: "Phishing. Single 'p' instead of double." },
        { id: 20, difficulty: 1, scenario: "YouTube Video.", url: "https://yuotube.com", isPhishing: true, explanation: "Phishing. Swapped 'u' and 'o'." },

        // --- LEVEL 3: TLD & Extension Spoofing ---
        { id: 21, difficulty: 2, scenario: "Amazon Deals.", url: "http://amazon-orders.net", isPhishing: true, explanation: "Phishing. Amazon uses `.com`, rarely `.net` for orders." },
        { id: 22, difficulty: 2, scenario: "Google Support.", url: "https://google-help.xyz", isPhishing: true, explanation: "Phishing. `.xyz` is common for spam. Google uses `google.com`." },
        { id: 23, difficulty: 2, scenario: "Netflix Billing.", url: "http://netflix.billing-update.info", isPhishing: true, explanation: "Phishing. The domain is `billing-update.info`." },
        { id: 24, difficulty: 2, scenario: "Office 365 Login.", url: "http://office365-login.org", isPhishing: true, explanation: "Phishing. Microsoft doesn't use `.org` for login portals." },
        { id: 25, difficulty: 2, scenario: "PayPal Secure.", url: "https://paypal-secure.biz", isPhishing: true, explanation: "Phishing. `.biz` is unprofessional and suspicious for a bank." },
        { id: 26, difficulty: 2, scenario: "Apple Store.", url: "http://apple-store.shop", isPhishing: true, explanation: "Phishing. Apple uses `apple.com`." },
        { id: 27, difficulty: 2, scenario: "Chase Bank.", url: "https://chase-bank.online", isPhishing: true, explanation: "Phishing. Major banks rarely use generic TLDs like `.online`." },
        { id: 28, difficulty: 2, scenario: "Zoom Invite.", url: "https://zoom-meetings.club", isPhishing: true, explanation: "Phishing. Zoom uses `zoom.us`." },
        { id: 29, difficulty: 2, scenario: "Slack Login.", url: "https://slack-workspace.site", isPhishing: true, explanation: "Phishing. Slack uses `slack.com`." },
        { id: 30, difficulty: 2, scenario: "Dropbox Share.", url: "https://dropbox-files.top", isPhishing: true, explanation: "Phishing. `.top` is a high-risk TLD." },

        // --- LEVEL 4: Subdomain Chaining (Right-to-Left Reading) ---
        { id: 31, difficulty: 2, scenario: "Apple ID Reset.", url: "http://apple.id.security-check.com", isPhishing: true, explanation: "Phishing. Real domain is `security-check.com`." },
        { id: 32, difficulty: 2, scenario: "PayPal Verification.", url: "https://paypal.com.secure-account.net", isPhishing: true, explanation: "Phishing. Real domain is `secure-account.net`." },
        { id: 33, difficulty: 2, scenario: "Google Drive.", url: "https://drive.google.com.files.sharing.io", isPhishing: true, explanation: "Phishing. Real domain is `sharing.io`." },
        { id: 34, difficulty: 2, scenario: "Amazon Prime.", url: "http://amazon.com-prime.rewards.club", isPhishing: true, explanation: "Phishing. Real domain is `rewards.club`." },
        { id: 35, difficulty: 2, scenario: "Facebook Login.", url: "https://login.facebook.com.account-recovery.yz", isPhishing: true, explanation: "Phishing. Real domain is `account-recovery.yz`." },
        { id: 36, difficulty: 2, scenario: "Bank Alert.", url: "https://chase.com.verify.login.alerts.net", isPhishing: true, explanation: "Phishing. Real domain is `alerts.net`." },
        { id: 37, difficulty: 2, scenario: "Microsoft Teams.", url: "https://teams.microsoft.com.meeting-join.net", isPhishing: true, explanation: "Phishing. Real domain is `meeting-join.net`." },
        { id: 38, difficulty: 2, scenario: "Netflix Free Month.", url: "http://netflix.com.free-offer.site", isPhishing: true, explanation: "Phishing. Real domain is `free-offer.site`." },
        { id: 39, difficulty: 2, scenario: "Internal HR.", url: "https://hr.google.com", isPhishing: false, explanation: "Safe. `hr` is a subdomain of `google.com`." },
        { id: 40, difficulty: 2, scenario: "Dev Portal.", url: "https://developer.apple.com", isPhishing: false, explanation: "Safe. `developer` is a subdomain of `apple.com`." },

        // --- LEVEL 5: Homograph Attacks (Unicode/Lookalikes) ---
        { id: 41, difficulty: 3, scenario: "Coinbase Login.", url: "https://www.coịnbasẹ.com", isPhishing: true, explanation: "Phishing. Dots under 'i' and 'e' (Vietnamese characters)." },
        { id: 42, difficulty: 3, scenario: "Apple Support.", url: "https://www.appIe.com", isPhishing: true, explanation: "Phishing. Capital 'I' (Eye) used instead of 'l' (El)." },
        { id: 43, difficulty: 3, scenario: "Google Login.", url: "https://www.googIe.com", isPhishing: true, explanation: "Phishing. Capital 'I' (Eye) instead of 'l' (El)." },
        { id: 44, difficulty: 3, scenario: "PayPal Secure.", url: "https://www.paypaI.com", isPhishing: true, explanation: "Phishing. Capital 'I' (Eye) instead of 'l' (El)." },
        { id: 45, difficulty: 3, scenario: "Amazon Shopping.", url: "https://www.arnazon.com", isPhishing: true, explanation: "Phishing. 'r' + 'n' looks like 'm'." },
        { id: 46, difficulty: 3, scenario: "Microsoft.", url: "https://www.rnicrosoft.com", isPhishing: true, explanation: "Phishing. 'r' + 'n' looks like 'm'." },
        { id: 47, difficulty: 3, scenario: "Epic Games.", url: "https://www.epicgarnes.com", isPhishing: true, explanation: "Phishing. 'r' + 'n' looks like 'm'." },
        { id: 48, difficulty: 3, scenario: "Instagram.", url: "https://www.instagram.co", isPhishing: true, explanation: "Phishing. Missing 'm' at the end (.co instead of .com)." },
        { id: 49, difficulty: 3, scenario: "Generic Bank.", url: "https://www.bạṅk.com", isPhishing: true, explanation: "Phishing. Accents on letters." },
        { id: 50, difficulty: 3, scenario: "Russian VK.", url: "https://vk.com", isPhishing: false, explanation: "Safe. Valid short domain." },

        // --- LEVEL 6: Hyphenated Confusion ---
        { id: 51, difficulty: 1, scenario: "Secure Login.", url: "http://paypal-secure-login.com", isPhishing: true, explanation: "Phishing. Attackers imply it's PayPal via hyphens." },
        { id: 52, difficulty: 1, scenario: "Amazon Prime.", url: "http://amazon-prime-video.net", isPhishing: true, explanation: "Phishing. Long hyphenated domain." },
        { id: 53, difficulty: 1, scenario: "Google Cloud.", url: "https://google-cloud-storage.com", isPhishing: true, explanation: "Phishing. Real domain is `cloud.google.com`." },
        { id: 54, difficulty: 1, scenario: "Apple Support.", url: "https://apple-support-center.com", isPhishing: true, explanation: "Phishing. Real domain is `support.apple.com`." },
        { id: 55, difficulty: 1, scenario: "Facebook Security.", url: "https://facebook-security-check.com", isPhishing: true, explanation: "Phishing. Real domain is `facebook.com`." },
        { id: 56, difficulty: 1, scenario: "Netflix Account.", url: "https://netflix-account-update.com", isPhishing: true, explanation: "Phishing. Real domain is `netflix.com`." },
        { id: 57, difficulty: 1, scenario: "Instagram Verify.", url: "https://instagram-verify-badge.com", isPhishing: true, explanation: "Phishing. Real domain is `instagram.com`." },
        { id: 58, difficulty: 1, scenario: "WhatsApp Backup.", url: "https://whatsapp-backup-restore.com", isPhishing: true, explanation: "Phishing. Real domain is `whatsapp.com`." },
        { id: 59, difficulty: 1, scenario: "Twitter Support.", url: "https://twitter-helpdesk.com", isPhishing: true, explanation: "Phishing. Real domain is `help.twitter.com`." },
        { id: 60, difficulty: 1, scenario: "LinkedIn Jobs.", url: "https://linkedin-jobs-apply.com", isPhishing: true, explanation: "Phishing. Real domain is `linkedin.com`." },

        // --- LEVEL 7: Brand Abuse (Tech Support) ---
        { id: 61, difficulty: 2, scenario: "Windows Virus Alert.", url: "http://microsoft-windows-support.com", isPhishing: true, explanation: "Phishing. Microsoft doesn't use `microsoft-windows-support.com`." },
        { id: 62, difficulty: 2, scenario: "McAfee Expiry.", url: "https://mcafee-renewal-discount.com", isPhishing: true, explanation: "Phishing. Fake renewal site." },
        { id: 63, difficulty: 2, scenario: "Norton Antivirus.", url: "http://norton-antivirus-check.com", isPhishing: true, explanation: "Phishing. Fake checker site." },
        { id: 64, difficulty: 2, scenario: "Geek Squad Help.", url: "https://geek-squad-remote-help.com", isPhishing: true, explanation: "Phishing. Fake support site." },
        { id: 65, difficulty: 2, scenario: "Adobe Flash Update.", url: "http://get-adobe-flash-player.com", isPhishing: true, explanation: "Phishing. Flash is dead, and the domain is fake." },
        { id: 66, difficulty: 2, scenario: "Zoom Installer.", url: "https://zoom-download-center.com", isPhishing: true, explanation: "Phishing. Real domain is `zoom.us/download`." },
        { id: 67, difficulty: 2, scenario: "Chrome Update.", url: "http://chrome-update-browser.com", isPhishing: true, explanation: "Phishing. Chrome updates automatically internally." },
        { id: 68, difficulty: 2, scenario: "Driver Update.", url: "https://hp-drivers-update.com", isPhishing: true, explanation: "Phishing. Real domain is `support.hp.com`." },
        { id: 69, difficulty: 2, scenario: "Dell Support.", url: "https://dell-laptop-support.com", isPhishing: true, explanation: "Phishing. Real domain is `dell.com`." },
        { id: 70, difficulty: 2, scenario: "Lenovo Drivers.", url: "http://lenovo-drivers-fix.com", isPhishing: true, explanation: "Phishing. Real domain is `lenovo.com`." },

        // --- LEVEL 8: File Vectors & Data URIs ---
        { id: 71, difficulty: 2, scenario: "PDF Invoice.", url: "data:text/html;base64,PHNjcmlwdD5hbGVydCgnaGFja2VkJyk8L3NjcmlwdD4=", isPhishing: true, explanation: "Phishing. Data URI contains executable code." },
        { id: 72, difficulty: 2, scenario: "Local File.", url: "file:///C:/Users/Admin/Downloads/invoice.exe", isPhishing: true, explanation: "Phishing. Links to local file execution." },
        { id: 73, difficulty: 2, scenario: "Script Execution.", url: "javascript:void(0)", isPhishing: true, explanation: "Phishing. JavaScript scheme can execute code." },
        { id: 74, difficulty: 2, scenario: "Blob URI.", url: "blob:https://mega.nz/12345", isPhishing: true, explanation: "Phishing. Blob URIs can hide malicious downloads." },
        { id: 75, difficulty: 2, scenario: "Fake Image.", url: "http://example.com/image.jpg.exe", isPhishing: true, explanation: "Phishing. Double extension trick." },

        // --- LEVEL 9: URL Shorteners & Obfuscation ---
        { id: 76, difficulty: 3, scenario: "Bitly Link.", url: "https://bit.ly/3x89a", isPhishing: true, explanation: "Phishing. Short links hide the destination." },
        { id: 77, difficulty: 3, scenario: "TinyURL.", url: "https://tinyurl.com/secure-login", isPhishing: true, explanation: "Phishing. Short links hide the destination." },
        { id: 78, difficulty: 3, scenario: "Open Redirect.", url: "https://google.com/url?q=http://evil.com", isPhishing: true, explanation: "Phishing. Redirects to `evil.com`." },
        { id: 79, difficulty: 3, scenario: "Username Obfuscation.", url: "https://google.com@evil.com", isPhishing: true, explanation: "Phishing. `@` symbol makes `google.com` the username." },
        { id: 80, difficulty: 3, scenario: "IP Address.", url: "http://45.33.22.11/login", isPhishing: true, explanation: "Phishing. Professional sites use domains, not IPs." },
        { id: 81, difficulty: 3, scenario: "Local Router.", url: "http://192.168.1.1", isPhishing: false, explanation: "Safe. Local router IP address." },
        { id: 82, difficulty: 3, scenario: "Localhost.", url: "http://127.0.0.1:3000", isPhishing: false, explanation: "Safe. Local development server." },
        { id: 83, difficulty: 3, scenario: "Discord Gift.", url: "https://dlscord.gg/gift", isPhishing: true, explanation: "Phishing. `dlscord` (L) instead of `discord`." },
        { id: 84, difficulty: 3, scenario: "Steam Trade.", url: "https://steamcommuniity.com", isPhishing: true, explanation: "Phishing. Double 'i' in community." },
        { id: 85, difficulty: 3, scenario: "Roblox Robux.", url: "https://roblox-free-robux.com", isPhishing: true, explanation: "Phishing. Fake free generator site." },

        // --- LEVEL 10: Mixed Bag (Final Exam) ---
        { id: 86, difficulty: 2, scenario: "Fortnite V-Bucks.", url: "https://fortnite-vbucks-generator.net", isPhishing: true, explanation: "Phishing. Fake generator site." },
        { id: 87, difficulty: 2, scenario: "Minecraft Skins.", url: "https://minecraft.net", isPhishing: false, explanation: "Safe. Official domain." },
        { id: 88, difficulty: 2, scenario: "Twitch Stream.", url: "https://twitch.tv", isPhishing: false, explanation: "Safe. Official domain." },
        { id: 89, difficulty: 2, scenario: "Twitch Drop.", url: "https://twitch-drops-claim.com", isPhishing: true, explanation: "Phishing. Fake claim site." },
        { id: 90, difficulty: 2, scenario: "Spotify Premium.", url: "https://spotify-premium-free.com", isPhishing: true, explanation: "Phishing. Fake upgrade site." },
        { id: 91, difficulty: 2, scenario: "Spotify Web Player.", url: "https://open.spotify.com", isPhishing: false, explanation: "Safe. Official subdomain." },
        { id: 92, difficulty: 2, scenario: "GitHub Repo.", url: "https://github.com", isPhishing: false, explanation: "Safe. Official domain." },
        { id: 93, difficulty: 2, scenario: "Fake GitHub.", url: "https://github-login.com", isPhishing: true, explanation: "Phishing. Fake login site." },
        { id: 94, difficulty: 1, scenario: "Wikipedia.", url: "https://wikipedia.org", isPhishing: false, explanation: "Safe. Official domain." },
        { id: 95, difficulty: 1, scenario: "Fake Wikipedia.", url: "https://wikipediia.org", isPhishing: true, explanation: "Phishing. Double 'i'." },
        { id: 96, difficulty: 2, scenario: "Reddit Thread.", url: "https://reddit.com", isPhishing: false, explanation: "Safe. Official domain." },
        { id: 97, difficulty: 2, scenario: "Fake Reddit.", url: "https://r-eddit.com", isPhishing: true, explanation: "Phishing. Added hyphen." },
        { id: 98, difficulty: 3, scenario: "StackOverflow.", url: "https://stackoverflow.com", isPhishing: false, explanation: "Safe. Official domain." },
        { id: 99, difficulty: 3, scenario: "Fake Stack.", url: "https://stack-overflow-login.com", isPhishing: true, explanation: "Phishing. Fake login." },
        { id: 100, difficulty: 3, scenario: "The End.", url: "https://phishingshield.io", isPhishing: false, explanation: "Safe. That's us!" }
    ],

    init: function () {
        this.bindEvents();
        this.loadNewQuestion();
    },

    bindEvents: function () {
        document.getElementById('btn-safe').addEventListener('click', () => this.checkAnswer(false));
        document.getElementById('btn-phish').addEventListener('click', () => this.checkAnswer(true));
        document.getElementById('btn-next').addEventListener('click', () => {
            document.getElementById('dojo-feedback').style.display = 'none';
            document.getElementById('btn-next').style.display = 'none';
            this.loadNewQuestion();
        });

        // Tab Switching Logic
        document.getElementById('tab-dashboard').addEventListener('click', () => this.switchTab('dashboard'));
        document.getElementById('tab-dojo').addEventListener('click', () => this.switchTab('dojo'));
    },

    switchTab: function (tabName) {
        document.querySelectorAll('.tab').forEach(t => {
            t.classList.remove('active');
            // Removed inline style resets to allow CSS to control appearance
            t.removeAttribute('style');
        });
        document.querySelectorAll('[id^="view-"]').forEach(v => v.style.display = 'none');

        const tab = document.getElementById(`tab-${tabName}`);
        tab.classList.add('active');
        // Removed inline active styles

        document.getElementById(`view-${tabName}`).style.display = 'block';
    },

    // Logic to highlight the 'domain' part of a URL similar to Chrome's address bar
    formatUrlForDisplay: function (urlString) {
        try {
            // Handle non-standard protocols or partials gracefully
            if (!urlString.startsWith('http')) return urlString;

            const urlObj = new URL(urlString);
            const domain = urlObj.hostname;
            const protocol = urlObj.protocol + "//";
            const rest = urlString.substring(protocol.length + domain.length);

            // Return HTML with domain bolded
            return `<span style="opacity:0.6">${protocol}</span><span style="color:#ffffff; font-weight:700; text-shadow:0 0 8px rgba(255,255,255,0.3);">${domain}</span><span style="opacity:0.6">${rest}</span>`;
        } catch (e) {
            return urlString;
        }
    },

    loadNewQuestion: function () {
        // Adaptive Difficulty Logic
        let allowedDifficulty = 1;
        if (this.streak > 2) allowedDifficulty = 2;
        if (this.streak > 5) allowedDifficulty = 3;

        // Filter questions based on current 'level' of streak
        const candidates = this.questions.filter(q => (q.difficulty || 1) <= allowedDifficulty);

        // Fallback to all if something goes wrong
        const pool = candidates.length > 0 ? candidates : this.questions;

        const randomIndex = Math.floor(Math.random() * pool.length);
        this.currentQuestion = pool[randomIndex];

        document.getElementById('dojo-scenario').textContent = this.currentQuestion.scenario;

        // Use the new formatter for the URL display
        const urlDisplay = document.getElementById('dojo-url');
        urlDisplay.innerHTML = this.formatUrlForDisplay(this.currentQuestion.url);

        // Reset Buttons
        document.getElementById('btn-safe').disabled = false;
        document.getElementById('btn-phish').disabled = false;

        // Hide previous visual cues
        urlDisplay.style.border = 'none';
        urlDisplay.style.background = 'transparent';
    },

    checkAnswer: function (userSaysPhishing) {
        const isCorrect = userSaysPhishing === this.currentQuestion.isPhishing;
        const feedbackEl = document.getElementById('dojo-feedback');
        const diff = this.currentQuestion.difficulty || 1;

        if (isCorrect) {
            this.streak++;

            // --- NEW BALANCED XP FORMULA ---
            let rawXp = (5 + (this.streak * 2));
            if (diff === 2) rawXp *= 1.5;
            if (diff === 3) rawXp *= 2;

            let xpReward = Math.floor(rawXp);

            let badges = `<span style="background:rgba(16,185,129,0.15); color:#34d399; padding:2px 8px; border-radius:4px; font-size:10px; border:1px solid rgba(16,185,129,0.4);">Difficulty ${diff}</span>`;

            // Streak Logic
            if (this.streak > 1) {
                badges += ` <span style="background:rgba(245,158,11,0.15); color:#fbbf24; padding:2px 8px; border-radius:4px; font-size:10px; border:1px solid rgba(245,158,11,0.4);">🔥 Streak x${this.streak}</span>`;
            }

            // Mega Bonus every 5 streaks (instead of 3)
            if (this.streak % 5 === 0) {
                xpReward += 50;
                badges += ` <span style="background:rgba(59,130,246,0.15); color:#60a5fa; padding:2px 8px; border-radius:4px; font-size:10px; border:1px solid rgba(59,130,246,0.4);">🚀 Mega Bonus +50</span>`;
            }

            let msg = `
                <div style="margin-bottom:8px;">${badges}</div>
                <div style="color: #34d399; font-weight: bold; font-size: 14px; margin-bottom: 4px;">Correct! 🎉</div>
                <div style="font-size: 12px; color: #cbd5e1; line-height: 1.4;">${this.currentQuestion.explanation}</div>
                <div style="margin-top:8px; font-weight:bold; color:#60a5fa; font-size: 12px;">+${xpReward} XP Earned</div>
            `;

            feedbackEl.innerHTML = msg;
            feedbackEl.style.border = "1px solid rgba(16, 185, 129, 0.4)";
            feedbackEl.style.background = "rgba(16, 185, 129, 0.1)";

            document.getElementById('dojo-url').style.border = "1px solid rgba(16, 185, 129, 0.5)";
            document.getElementById('dojo-url').style.background = "rgba(16, 185, 129, 0.08)";

            this.grantXP(xpReward);
        } else {
            this.streak = 0; // Reset streak
            let msg = `
                <div style="color: #f87171; font-weight: bold; font-size: 14px; margin-bottom: 4px;">Oops! Wrong. 💀</div>
                <div style="font-size: 12px; color: #cbd5e1; line-height: 1.4;">${this.currentQuestion.explanation}</div>
                <div style="margin-top:8px; font-size: 11px; color:#94a3b8;">Streak lost. Back to 0.</div>
            `;

            feedbackEl.innerHTML = msg;
            feedbackEl.style.border = "1px solid rgba(239, 68, 68, 0.4)";
            feedbackEl.style.background = "rgba(239, 68, 68, 0.1)";

            document.getElementById('dojo-url').style.border = "1px solid rgba(239, 68, 68, 0.5)";
            document.getElementById('dojo-url').style.background = "rgba(239, 68, 68, 0.08)";
        }

        feedbackEl.style.display = 'block';
        document.getElementById('btn-next').style.display = 'block';

        // Disable buttons
        document.getElementById('btn-safe').disabled = true;
        document.getElementById('btn-phish').disabled = true;
    },

    grantXP: function (amount) {
        chrome.storage.local.get(['userXP', 'userLevel'], (result) => {
            let xp = result.userXP || 0;
            let level = result.userLevel || 1;

            xp += amount;

            // Level Up Calculation (Level^2 * 100)
            const nextLevelXp = Math.pow(level, 2) * 100;
            if (xp >= nextLevelXp) {
                level++;
                // xp = 0; // FIXED: Do not reset XP, it is cumulative!
                // alert(`Level Up! You are now Level ${level}`); 
            }

            chrome.storage.local.set({ userXP: xp, userLevel: level, pendingXPSync: true }, () => {
                // Refresh UI if visible
                if (window.updateSafetyLevel) window.updateSafetyLevel();

                // Trigger Cloud Sync if Auth available
                if (typeof Auth !== 'undefined' && Auth.syncXP) Auth.syncXP();
            });
        });
    }
};

// Initialize when DOM is ready (popup.js handles this order usually, but safer here too)
// We will call Dojo.init() from popup.js
