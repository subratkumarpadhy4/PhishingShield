/**
 * PhishingShield Chameleon Engine (Visual DNA Detection)
 * Version: 4.0 (Gigantic Database - 200+ Signatures)
 * 
 * THE PROBLEM: 
 * Traditional scanners check if the URL is "bad". 
 * Phishers bypass this by using "clean" URLs (e.g. secure-login.net) 
 * hosting "perfect" visual clones of brands.
 * 
 * THE SOLUTION:
 * Chameleon ignores the URL. It looks at the "Visual DNA" of the page.
 * If a page LOOKS like PayPal but ISN'T paypal.com -> BLOCK.
 */

const Chameleon = {
    // 200+ Top Target Signatures (The "DNA" Database)
    signatures: {
        // =======================
        // 1. TECH GIANTS (The Big 5+)
        // =======================
        google: {
            colors: ['#4285f4', '#ea4335'],
            keywords: ['sign in', 'continue to gmail', 'forgot email'],
            logoHints: ['google_logo', 'branding/googlelogo', 'google_white_logo'],
            titleKeywords: ['Sign in - Google Accounts', 'Google Drive', 'Gmail'],
            officialDomains: ['google.com', 'accounts.google.com', 'youtube.com', 'gmail.com', 'drive.google.com']
        },
        microsoft: {
            colors: ['#f25022', '#7fba00', '#00a4ef', '#ffb900'],
            keywords: ['sign in', 'microsoft account', 'skype', 'no account?'],
            logoHints: ['microsoft_logo', 'microsoft-logo', 'ms-symbollockup'],
            titleKeywords: ['Sign in to your account', 'Microsoft account'],
            officialDomains: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'azure.com', 'sharepoint.com']
        },
        apple: {
            colors: ['#000000', '#f5f5f7'],
            keywords: ['apple id', 'manage your apple account', 'icloud'],
            logoHints: ['apple_logo', 'apple-logo'],
            titleKeywords: ['Apple ID', 'iCloud'],
            officialDomains: ['apple.com', 'icloud.com']
        },
        amazon: {
            colors: ['#ff9900', '#146eb4'],
            keywords: ['sign-in', 'email or mobile phone number', 'amazon password'],
            logoHints: ['amazon_logo', 'nav-logo-base'],
            titleKeywords: ['Amazon Sign-In', 'Amazon.com'],
            officialDomains: ['amazon.com', 'amazon.co.uk', 'amazon.in', 'aws.amazon.com']
        },
        meta: {
            colors: ['#1877f2', '#42b72a'],
            keywords: ['log in', 'create new account', 'forgot password?'],
            logoHints: ['facebook_logo', 'fb_logo', 'meta_logo'],
            titleKeywords: ['Facebook - Log In', 'Instagram', 'Log in to Facebook'],
            officialDomains: ['facebook.com', 'messenger.com', 'meta.com', 'instagram.com', 'whatsapp.com']
        },
        netflix: {
            colors: ['#e50914'],
            keywords: ['sign in', 'netflix', 'unlimited movies'],
            logoHints: ['netflix_logo', 'netflix-logo'],
            titleKeywords: ['Netflix'],
            officialDomains: ['netflix.com']
        },

        // =======================
        // 2. SOCIAL MEDIA
        // =======================
        twitter: { colors: ['#1d9bf0', '#000000'], keywords: ['sign in to x', 'log in', 'twitter'], officialDomains: ['twitter.com', 'x.com'] },
        linkedin: { colors: ['#0a66c2'], keywords: ['sign in', 'join now', 'linkedin'], officialDomains: ['linkedin.com'] },
        instagram: { colors: ['#e1306c'], keywords: ['log in', 'instagram'], logoHints: ['instagram_logo'], officialDomains: ['instagram.com'] },
        tiktok: { colors: ['#000000', '#fe2c55', '#25f4ee'], keywords: ['log in', 'tiktok'], officialDomains: ['tiktok.com'] },
        pinterest: { colors: ['#bd081c'], keywords: ['log in', 'pinterest', 'sign up'], officialDomains: ['pinterest.com'] },
        reddit: { colors: ['#ff4500'], keywords: ['log in', 'reddit'], officialDomains: ['reddit.com'] },
        discord: { colors: ['#5865f2'], keywords: ['login', 'discord', 'welcome back'], logoHints: ['discord_logo'], officialDomains: ['discord.com'] },
        snapchat: { colors: ['#fffc00'], keywords: ['log in', 'snapchat'], officialDomains: ['snapchat.com'] },
        tumblr: { colors: ['#36465d'], keywords: ['log in', 'tumblr'], officialDomains: ['tumblr.com'] },
        telegram: { colors: ['#0088cc'], keywords: ['telegram web', 'log in'], officialDomains: ['telegram.org', 'web.telegram.org'] },
        whatsapp: { colors: ['#25d366'], keywords: ['whatsapp web', 'use whatsapp on your computer'], officialDomains: ['whatsapp.com', 'web.whatsapp.com'] },
        skype: { colors: ['#00aff0'], keywords: ['sign in', 'skype'], officialDomains: ['skype.com'] },

        // =======================
        // 3. FINANCE & BANKING (USA/GLOBAL) - HIGH RISK
        // =======================
        paypal: { colors: ['#003087', '#0070ba'], keywords: ['log in', 'sign up'], logoHints: ['paypal_logo'], officialDomains: ['paypal.com'] },
        chase: { colors: ['#117aca'], keywords: ['welcome', 'username', 'password', 'chase'], officialDomains: ['chase.com'] },
        bofa: { colors: ['#e31837', '#0061aa'], keywords: ['sign in', 'online id', 'bank of america'], officialDomains: ['bankofamerica.com'] },
        wellsfargo: { colors: ['#d71e28'], keywords: ['sign on', 'enroll', 'wells fargo'], officialDomains: ['wellsfargo.com'] },
        citi: { colors: ['#003b70', '#ee2724'], keywords: ['sign on', 'user id', 'citi'], officialDomains: ['citi.com'] },
        capitalone: { colors: ['#004977', '#d03027'], keywords: ['sign in', 'username', 'capital one'], officialDomains: ['capitalone.com'] },
        amex: { colors: ['#006fcf'], keywords: ['log in', 'user id', 'american express'], officialDomains: ['americanexpress.com'] },
        usbank: { colors: ['#0c2074', '#de162b'], keywords: ['log in', 'u.s. bank'], officialDomains: ['usbank.com'] },
        pnc: { colors: ['#f47c20'], keywords: ['sign on', 'pnc'], officialDomains: ['pnc.com'] },
        truist: { colors: ['#2e1a47'], keywords: ['sign in', 'truist'], officialDomains: ['truist.com'] },
        tdbank: { colors: ['#008a00'], keywords: ['log in', 'td bank'], officialDomains: ['td.com', 'tdbank.com'] },
        schwab: { colors: ['#00a0dd'], keywords: ['login', 'charles schwab'], officialDomains: ['schwab.com'] },
        fidelity: { colors: ['#125e36'], keywords: ['log in', 'fidelity'], officialDomains: ['fidelity.com'] },
        goldmansachs: { colors: ['#7399c6'], keywords: ['login', 'goldman sachs'], officialDomains: ['goldmansachs.com', 'gs.com'] },
        morganstanley: { colors: ['#000000'], keywords: ['login', 'morgan stanley'], officialDomains: ['morganstanley.com'] },
        robinhood: { colors: ['#00c805'], keywords: ['log in', 'robinhood'], officialDomains: ['robinhood.com'] },

        // =======================
        // 4. INTERNATIONAL BANKING
        // =======================
        hsbc: { colors: ['#db0011'], keywords: ['log on', 'username', 'hsbc'], officialDomains: ['hsbc.com', 'hsbc.co.uk'] },
        barclays: { colors: ['#00aeef'], keywords: ['log in', 'surname', 'barclays'], officialDomains: ['barclays.co.uk'] },
        lloyds: { colors: ['#006a4d'], keywords: ['log on', 'lloyds bank'], officialDomains: ['lloydsbank.com'] },
        natwest: { colors: ['#42145f'], keywords: ['log in', 'natwest'], officialDomains: ['natwest.com'] },
        santander: { colors: ['#ec0000'], keywords: ['log on', 'santander'], officialDomains: ['santander.co.uk', 'santanderbank.com'] },
        rbc: { colors: ['#0051a5', '#ffc425'], keywords: ['sign in', 'rbc royal bank'], officialDomains: ['rbc.com', 'rbcroyalbank.com'] },
        scotiabank: { colors: ['#ec111a'], keywords: ['sign in', 'scotiabank'], officialDomains: ['scotiabank.com'] },
        bmo: { colors: ['#0079c1'], keywords: ['sign in', 'bmo'], officialDomains: ['bmo.com'] },
        td_canada: { colors: ['#008a00'], keywords: ['login', 'easyweb'], officialDomains: ['td.com'] },
        anz: { colors: ['#004165'], keywords: ['log on', 'anz'], officialDomains: ['anz.com.au'] },
        westpac: { colors: ['#da1710'], keywords: ['sign in', 'westpac'], officialDomains: ['westpac.com.au'] },
        commbank: { colors: ['#ffcc00'], keywords: ['log on', 'commbank'], officialDomains: ['commbank.com.au'] },
        nab: { colors: ['#bf0d3e'], keywords: ['login', 'nab'], officialDomains: ['nab.com.au'] },
        deutsche: { colors: ['#0018a8'], keywords: ['login', 'deutsche bank'], officialDomains: ['db.com', 'deutsche-bank.de'] },
        ubs: { colors: ['#000000'], keywords: ['login', 'ubs'], officialDomains: ['ubs.com'] },
        credit_suisse: { colors: ['#000000'], keywords: ['login', 'credit suisse'], officialDomains: ['credit-suisse.com'] },
        ing: { colors: ['#ff6200'], keywords: ['log in', 'ing'], officialDomains: ['ing.com', 'ing.com.au'] },
        rabobank: { colors: ['#fd6400'], keywords: ['login', 'rabobank'], officialDomains: ['rabobank.com', 'rabobank.nl'] },

        // =======================
        // 5. CRYPTO & WALLETS (Highest Risk)
        // =======================
        coinbase: { colors: ['#0052ff'], keywords: ['sign in', 'coinbase'], logoHints: ['coinbase_logo'], officialDomains: ['coinbase.com'] },
        binance: { colors: ['#f0b90b'], keywords: ['log in', 'binance'], logoHints: ['binance_logo'], officialDomains: ['binance.com'] },
        kraken: { colors: ['#5841d8'], keywords: ['sign in', 'kraken'], officialDomains: ['kraken.com'] },
        kucoin: { colors: ['#00a38d'], keywords: ['log in', 'kucoin'], officialDomains: ['kucoin.com'] },
        crypto_com: { colors: ['#002d74'], keywords: ['log in', 'crypto.com'], officialDomains: ['crypto.com'] },
        gemini: { colors: ['#00dcfa'], keywords: ['sign in', 'gemini'], officialDomains: ['gemini.com'] },
        gate_io: { colors: ['#bf3936'], keywords: ['log in', 'gate.io'], officialDomains: ['gate.io'] },
        bybit: { colors: ['#f7a600'], keywords: ['login', 'bybit'], officialDomains: ['bybit.com'] },
        okx: { colors: ['#000000'], keywords: ['login', 'okx'], officialDomains: ['okx.com'] },
        bitfinex: { colors: ['#13aa4f'], keywords: ['login', 'bitfinex'], officialDomains: ['bitfinex.com'] },
        metamask: { colors: ['#f6851b'], keywords: ['welcome back', 'unlock', 'metamask'], logoHints: ['metamask-logo'], officialDomains: ['metamask.io'] },
        phantom: { colors: ['#ab9ff2'], keywords: ['unlock', 'phantom'], officialDomains: ['phantom.app'] },
        trustwallet: { colors: ['#3375bb'], keywords: ['trust wallet', 'login'], officialDomains: ['trustwallet.com'] },
        ledger: { colors: ['#000000'], keywords: ['ledger live', 'connect'], officialDomains: ['ledger.com'] },
        trezor: { colors: ['#00854d'], keywords: ['trezor suite', 'connect'], officialDomains: ['trezor.io'] },
        blockchain: { colors: ['#121d33'], keywords: ['login', 'wallet', 'blockchain'], officialDomains: ['blockchain.com'] },
        exodus: { colors: ['#5e5ce6'], keywords: ['exodus', 'wallet'], officialDomains: ['exodus.com'] },
        myetherwallet: { colors: ['#05c0a5'], keywords: ['access my wallet', 'mew'], officialDomains: ['myetherwallet.com'] },

        // =======================
        // 6. PAYMENT PROCESSORS
        // =======================
        stripe: { colors: ['#635bff'], keywords: ['sign in', 'stripe'], officialDomains: ['stripe.com'] },
        square: { colors: ['#000000'], keywords: ['sign in', 'square'], officialDomains: ['squareup.com'] },
        wise: { colors: ['#9ce657'], keywords: ['log in', 'wise'], officialDomains: ['wise.com'] },
        revolut: { colors: ['#0075eb'], keywords: ['log in', 'revolut'], officialDomains: ['revolut.com'] },
        cashapp: { colors: ['#00d632'], keywords: ['sign in', 'cash app'], officialDomains: ['cash.app'] },
        venmo: { colors: ['#008cff'], keywords: ['sign in', 'venmo'], officialDomains: ['venmo.com'] },
        westernunion: { colors: ['#ffda00'], keywords: ['money transfer', 'log in'], officialDomains: ['westernunion.com'] },
        moneygram: { colors: ['#e2001a'], keywords: ['log in', 'moneygram'], officialDomains: ['moneygram.com'] },
        skrill: { colors: ['#811e4d'], keywords: ['log in', 'skrill'], officialDomains: ['skrill.com'] },
        neteller: { colors: ['#8dc63f'], keywords: ['sign in', 'neteller'], officialDomains: ['neteller.com'] },
        payoneer: { colors: ['#ff4800'], keywords: ['sign in', 'payoneer'], officialDomains: ['payoneer.com'] },

        // =======================
        // 7. E-COMMERCE & RETAIL
        // =======================
        ebay: { colors: ['#e53238', '#0064d2'], keywords: ['sign in', 'ebay'], officialDomains: ['ebay.com'] },
        walmart: { colors: ['#0071dc'], keywords: ['sign in', 'walmart'], officialDomains: ['walmart.com'] },
        target: { colors: ['#cc0000'], keywords: ['sign in', 'target'], officialDomains: ['target.com'] },
        bestbuy: { colors: ['#0046be'], keywords: ['sign in', 'best buy'], officialDomains: ['bestbuy.com'] },
        alibaba: { colors: ['#ff6a00'], keywords: ['sign in', 'alibaba'], officialDomains: ['alibaba.com'] },
        aliexpress: { colors: ['#ff4747'], keywords: ['sign in', 'aliexpress'], officialDomains: ['aliexpress.com'] },
        rakuten: { colors: ['#bf0000'], keywords: ['sign in', 'rakuten'], officialDomains: ['rakuten.com'] },
        shopify: { colors: ['#95bf47'], keywords: ['log in', 'shopify'], officialDomains: ['shopify.com'] },
        etsy: { colors: ['#f16521'], keywords: ['sign in', 'etsy'], officialDomains: ['etsy.com'] },
        costco: { colors: ['#0060a9'], keywords: ['sign in', 'costco'], officialDomains: ['costco.com'] },
        homedepot: { colors: ['#f96302'], keywords: ['sign in', 'home depot'], officialDomains: ['homedepot.com'] },
        lowes: { colors: ['#004990'], keywords: ['sign in', 'lowe\'s'], officialDomains: ['lowes.com'] },
        macys: { colors: ['#e01a2b'], keywords: ['sign in', 'macy\'s'], officialDomains: ['macys.com'] },
        kohls: { colors: ['#2e4198'], keywords: ['sign in', 'kohl\'s'], officialDomains: ['kohls.com'] },
        wayfair: { colors: ['#7f187f'], keywords: ['sign in', 'wayfair'], officialDomains: ['wayfair.com'] },
        ikea: { colors: ['#0051ba', '#ffda1a'], keywords: ['login', 'ikea'], officialDomains: ['ikea.com'] },
        nike: { colors: ['#000000'], keywords: ['sign in', 'nike'], officialDomains: ['nike.com'] },
        adidas: { colors: ['#000000'], keywords: ['log in', 'adidas'], officialDomains: ['adidas.com'] },
        shein: { colors: ['#000000'], keywords: ['sign in', 'shein'], officialDomains: ['shein.com'] },
        temu: { colors: ['#fb7701'], keywords: ['sign in', 'temu'], officialDomains: ['temu.com'] },

        // =======================
        // 8. EMAIL, ISP & TELECOM
        // =======================
        yahoo: { colors: ['#6001d2'], keywords: ['sign in', 'yahoo'], officialDomains: ['yahoo.com', 'login.yahoo.com'] },
        aol: { colors: ['#333333'], keywords: ['login', 'aol'], officialDomains: ['aol.com', 'login.aol.com'] },
        outlook: { colors: ['#0078d4'], keywords: ['sign in', 'outlook'], officialDomains: ['outlook.live.com', 'hotmail.com'] },
        att: { colors: ['#00a8e0'], keywords: ['sign in', 'at&t'], officialDomains: ['att.com'] },
        verizon: { colors: ['#cd040b'], keywords: ['sign in', 'verizon'], officialDomains: ['verizon.com'] },
        tmobile: { colors: ['#ea0a8e'], keywords: ['log in', 't-mobile'], officialDomains: ['t-mobile.com'] },
        xfinity: { colors: ['#613393'], keywords: ['sign in', 'xfinity'], officialDomains: ['xfinity.com'] },
        spectrum: { colors: ['#005ba7'], keywords: ['sign in', 'spectrum'], officialDomains: ['spectrum.net'] },
        cox: { colors: ['#00549f'], keywords: ['sign in', 'cox'], officialDomains: ['cox.com'] },
        centurylink: { colors: ['#0047bb'], keywords: ['sign in', 'centurylink'], officialDomains: ['centurylink.com'] },
        bt: { colors: ['#5514b4'], keywords: ['log in', 'bt email'], officialDomains: ['bt.com'] },
        virginmedia: { colors: ['#ed0000'], keywords: ['sign in', 'virgin media'], officialDomains: ['virginmedia.com'] },
        orange: { colors: ['#ff7900'], keywords: ['identifiez-vous', 'orange'], officialDomains: ['orange.fr', 'orange.com'] },
        vodafone: { colors: ['#e60000'], keywords: ['log in', 'vodafone'], officialDomains: ['vodafone.com', 'vodafone.co.uk'] },
        deutsche_telekom: { colors: ['#e20074'], keywords: ['login', 'telekom'], officialDomains: ['telekom.de'] },

        // =======================
        // 9. LOGISTICS & SHIPPING (Package Phishing)
        // =======================
        fedex: { colors: ['#4d148c', '#ff6600'], keywords: ['tracking', 'fedex', 'login'], officialDomains: ['fedex.com'] },
        ups: { colors: ['#351c15', '#ffb500'], keywords: ['tracking', 'ups', 'log in'], officialDomains: ['ups.com'] },
        dhl: { colors: ['#d40511', '#ffcc00'], keywords: ['tracking', 'dhl'], officialDomains: ['dhl.com'] },
        usps: { colors: ['#333366'], keywords: ['tracking', 'usps', 'sign in'], officialDomains: ['usps.com'] },
        royalmail: { colors: ['#d71921'], keywords: ['tracking', 'royal mail'], officialDomains: ['royalmail.com'] },
        canadapost: { colors: ['#0061a5'], keywords: ['sign in', 'canada post'], officialDomains: ['canadapost.ca'] },
        auspost: { colors: ['#dc1928'], keywords: ['track', 'australia post'], officialDomains: ['auspost.com.au'] },

        // =======================
        // 10. PRODUCTIVITY & CLOUD
        // =======================
        dropbox: { colors: ['#0061fe'], keywords: ['sign in', 'dropbox'], officialDomains: ['dropbox.com'] },
        box: { colors: ['#0061d5'], keywords: ['sign in', 'box'], officialDomains: ['box.com'] },
        adobe: { colors: ['#fa0f00'], keywords: ['sign in', 'adobe'], officialDomains: ['adobe.com'] },
        docusign: { colors: ['#2d3a46'], keywords: ['sign in', 'docusign'], officialDomains: ['docusign.com'] },
        zoom: { colors: ['#2d8cff'], keywords: ['sign in', 'zoom'], officialDomains: ['zoom.us'] },
        slack: { colors: ['#4a154b'], keywords: ['sign in', 'slack'], officialDomains: ['slack.com'] },
        salesforce: { colors: ['#00a1e0'], keywords: ['login', 'salesforce'], officialDomains: ['salesforce.com'] },
        gitlab: { colors: ['#fc6d26'], keywords: ['sign in', 'gitlab'], officialDomains: ['gitlab.com'] },
        github: { colors: ['#000000'], keywords: ['sign in', 'github'], officialDomains: ['github.com'] },
        atlassian: { colors: ['#0052cc'], keywords: ['log in', 'atlassian', 'jira', 'trello'], officialDomains: ['atlassian.com', 'trello.com'] },
        bitbucket: { colors: ['#0052cc'], keywords: ['log in', 'bitbucket'], officialDomains: ['bitbucket.org'] },
        aws: { colors: ['#232f3e'], keywords: ['sign in', 'aws console'], officialDomains: ['aws.amazon.com'] },
        heroku: { colors: ['#430098'], keywords: ['log in', 'heroku'], officialDomains: ['heroku.com'] },
        digitalocean: { colors: ['#0080ff'], keywords: ['log in', 'digitalocean'], officialDomains: ['digitalocean.com'] },
        oracle: { colors: ['#c74634'], keywords: ['sign in', 'oracle'], officialDomains: ['oracle.com'] },
        ibm: { colors: ['#006699'], keywords: ['log in', 'ibm'], officialDomains: ['ibm.com'] },
        cisco: { colors: ['#1ba0d7'], keywords: ['log in', 'cisco'], officialDomains: ['cisco.com'] },
        teamviewer: { colors: ['#004e9c'], keywords: ['sign in', 'teamviewer'], officialDomains: ['teamviewer.com'] },
        webex: { colors: ['#00bceb'], keywords: ['sign in', 'webex'], officialDomains: ['webex.com'] },
        logmein: { colors: ['#000000'], keywords: ['sign in', 'logmein'], officialDomains: ['logmein.com'] },

        // =======================
        // 11. ENTERTAINMENT & GAMING
        // =======================
        steam: { colors: ['#171a21'], keywords: ['login', 'steam'], officialDomains: ['steampowered.com', 'steamcommunity.com'] },
        roblox: { colors: ['#000000'], keywords: ['login', 'roblox'], officialDomains: ['roblox.com'] },
        twitch: { colors: ['#9146ff'], keywords: ['log in', 'twitch'], officialDomains: ['twitch.tv'] },
        epicgames: { colors: ['#303030'], keywords: ['sign in', 'epic games'], officialDomains: ['epicgames.com'] },
        blizzard: { colors: ['#009cde'], keywords: ['log in', 'blizzard'], officialDomains: ['battle.net', 'blizzard.com'] },
        playstation: { colors: ['#003791'], keywords: ['sign in', 'playstation'], officialDomains: ['playstation.com'] },
        xbox: { colors: ['#107c10'], keywords: ['sign in', 'xbox'], officialDomains: ['xbox.com'] },
        nintendo: { colors: ['#e60012'], keywords: ['sign in', 'nintendo'], officialDomains: ['nintendo.com'] },
        riotgames: { colors: ['#d13639'], keywords: ['sign in', 'riot games'], officialDomains: ['riotgames.com'] },
        ea: { colors: ['#ff4747'], keywords: ['sign in', 'ea'], officialDomains: ['ea.com'] },
        ubisoft: { colors: ['#000000'], keywords: ['log in', 'ubisoft'], officialDomains: ['ubisoft.com'] },
        minecraft: { colors: ['#464646'], keywords: ['log in', 'minecraft'], officialDomains: ['minecraft.net'] },
        spotify: { colors: ['#1db954'], keywords: ['log in', 'spotify'], officialDomains: ['spotify.com'] },
        apple_music: { colors: ['#fa243c'], keywords: ['sign in', 'apple music'], officialDomains: ['music.apple.com'] },
        disneyplus: { colors: ['#113ccf'], keywords: ['log in', 'disney+'], officialDomains: ['disneyplus.com'] },
        hulu: { colors: ['#1ce783'], keywords: ['log in', 'hulu'], officialDomains: ['hulu.com'] },
        hbo: { colors: ['#5400ff'], keywords: ['sign in', 'hbo max'], officialDomains: ['hbase.com', 'max.com'] },
        youtube: { colors: ['#ff0000'], keywords: ['sign in', 'youtube'], officialDomains: ['youtube.com'] },

        // =======================
        // 12. TRAVEL & AIRLINES
        // =======================
        airbnb: { colors: ['#ff5a5f'], keywords: ['login', 'airbnb'], officialDomains: ['airbnb.com'] },
        booking: { colors: ['#003580'], keywords: ['sign in', 'booking.com'], officialDomains: ['booking.com'] },
        expedia: { colors: ['#00257a'], keywords: ['sign in', 'expedia'], officialDomains: ['expedia.com'] },
        tripadvisor: { colors: ['#00af87'], keywords: ['sign in', 'tripadvisor'], officialDomains: ['tripadvisor.com'] },
        uber: { colors: ['#000000'], keywords: ['log in', 'uber'], officialDomains: ['uber.com'] },
        lyft: { colors: ['#ff00bf'], keywords: ['log in', 'lyft'], officialDomains: ['lyft.com'] },
        delta: { colors: ['#003a70'], keywords: ['log in', 'delta'], officialDomains: ['delta.com'] },
        united: { colors: ['#005da4'], keywords: ['sign in', 'united airlines'], officialDomains: ['united.com'] },
        americanairlines: { colors: ['#0078d2'], keywords: ['log in', 'american airlines'], officialDomains: ['aa.com'] },
        southwest: { colors: ['#304cb2'], keywords: ['log in', 'southwest'], officialDomains: ['southwest.com'] },
        britishairways: { colors: ['#075aaa'], keywords: ['log in', 'british airways'], officialDomains: ['britishairways.com'] },
        lufthansa: { colors: ['#05164d'], keywords: ['log in', 'lufthansa'], officialDomains: ['lufthansa.com'] },
        emirates: { colors: ['#d71920'], keywords: ['log in', 'emirates'], officialDomains: ['emirates.com'] },
        ryanair: { colors: ['#073590'], keywords: ['log in', 'ryanair'], officialDomains: ['ryanair.com'] },
        easyjet: { colors: ['#ff6600'], keywords: ['sign in', 'easyjet'], officialDomains: ['easyjet.com'] },
        agoda: { colors: ['#363636'], keywords: ['sign in', 'agoda'], officialDomains: ['agoda.com'] },
        hotels_com: { colors: ['#d32f2f'], keywords: ['sign in', 'hotels.com'], officialDomains: ['hotels.com'] },

        // =======================
        // 13. GOVERNMENT & INSTITUTIONS
        // =======================
        irs: { colors: ['#005ea2'], keywords: ['internal revenue service', 'payment'], officialDomains: ['irs.gov'] },
        uk_gov: { colors: ['#000000'], keywords: ['sign in', 'gov.uk'], officialDomains: ['gov.uk'] },
        usa_gov: { colors: ['#002868'], keywords: ['usa.gov'], officialDomains: ['usa.gov'] },
        id_me: { colors: ['#2c8c45'], keywords: ['sign in', 'id.me'], officialDomains: ['id.me'] },
        who: { colors: ['#0093d5'], keywords: ['login', 'world health organization'], officialDomains: ['who.int'] },
        un: { colors: ['#009edb'], keywords: ['login', 'united nations'], officialDomains: ['un.org'] },
        europa: { colors: ['#004494'], keywords: ['login', 'european union'], officialDomains: ['europa.eu'] },
        nasa: { colors: ['#0b3d91'], keywords: ['login', 'nasa'], officialDomains: ['nasa.gov'] },
        nih: { colors: ['#333333'], keywords: ['login', 'national institutes of health'], officialDomains: ['nih.gov'] },
        cdc: { colors: ['#005eaa'], keywords: ['login', 'centers for disease control'], officialDomains: ['cdc.gov'] },

        // =======================
        // 14. SERVICES & UTILITIES
        // =======================
        wordpress: { colors: ['#21759b'], keywords: ['log in', 'wordpress'], officialDomains: ['wordpress.com', 'wordpress.org'] },
        wix: { colors: ['#000000'], keywords: ['log in', 'wix'], officialDomains: ['wix.com'] },
        squarespace: { colors: ['#000000'], keywords: ['log in', 'squarespace'], officialDomains: ['squarespace.com'] },
        godaddy: { colors: ['#1bdbdb'], keywords: ['sign in', 'godaddy'], officialDomains: ['godaddy.com'] },
        namecheap: { colors: ['#de3723'], keywords: ['sign in', 'namecheap'], officialDomains: ['namecheap.com'] },
        bluehost: { colors: ['#283593'], keywords: ['log in', 'bluehost'], officialDomains: ['bluehost.com'] },
        hostgator: { colors: ['#ffc425'], keywords: ['sign in', 'hostgator'], officialDomains: ['hostgator.com'] },
        eventbrite: { colors: ['#f05537'], keywords: ['log in', 'eventbrite'], officialDomains: ['eventbrite.com'] },
        meetup: { colors: ['#ed1c40'], keywords: ['log in', 'meetup'], officialDomains: ['meetup.com'] },
        patreon: { colors: ['#f96854'], keywords: ['log in', 'patreon'], officialDomains: ['patreon.com'] },
        onlyfans: { colors: ['#00aff0'], keywords: ['log in', 'onlyfans'], officialDomains: ['onlyfans.com'] },
        medium: { colors: ['#000000'], keywords: ['sign in', 'medium'], officialDomains: ['medium.com'] },
        substack: { colors: ['#ff6719'], keywords: ['sign in', 'substack'], officialDomains: ['substack.com'] }
    },

    /**
     * Entry Point: Scans the current page's DOM for imposters.
     */
    scan: function () {
        // 1. Get current hostname
        const currentHost = window.location.hostname;

        // 2. Scan visual features
        const pageText = document.body.innerText.toLowerCase();
        const htmlLower = document.body.innerHTML.toLowerCase();
        const pageTitle = document.title.toLowerCase();
        const hasPasswordField = document.querySelector('input[type="password"]') !== null;

        let maxSimilarity = 0;
        let detectedBrand = null;
        let detectedReason = [];

        // Performance Check: Use a subset or optimize if too slow? 
        // JS loop over 200 items is fast (sub-10ms), so no premature optimization needed.
        const signatureCount = Object.keys(this.signatures).length;
        console.log(`[Chameleon] 🦎 Scanning ${currentHost} against ${signatureCount} Visual DNA signatures...`);

        // 3. Compare against DNA Database
        for (const [brand, dna] of Object.entries(this.signatures)) {
            const isOfficial = dna.officialDomains.some(d => currentHost.endsWith(d));
            if (isOfficial) continue;

            let score = 0;
            let reasons = [];

            // A. LOGO MATCH (40 Pts) - High Confidence
            if (dna.logoHints && this.checkLogos(dna.logoHints, htmlLower)) {
                score += 40;
                reasons.push("Logo Detected");
            }

            // B. TITLE MATCH (30 Pts)
            if (dna.titleKeywords && dna.titleKeywords.some(kw => pageTitle.includes(kw.toLowerCase()))) {
                score += 30;
                reasons.push("Title Match");
            }

            // C. KEYWORD MATCH (20 Pts)
            let keywordMatches = 0;
            if (dna.keywords) {
                dna.keywords.forEach(kw => {
                    if (pageText.includes(kw)) keywordMatches++;
                });
            }
            if (keywordMatches >= 2) {
                score += 20;
                reasons.push("Keyword Pattern");
            }

            // D. COLOR MATCH (10 Pts)
            let visualMatches = 0;
            if (dna.colors) {
                dna.colors.forEach(col => {
                    if (htmlLower.includes(col.toLowerCase())) visualMatches++;
                });
            }
            if (visualMatches >= 1) {
                score += 10;
            }

            // E. GENERIC SUSPICION
            if (score > 10 && hasPasswordField) {
                score += 15;
                reasons.push("Login Form Detected");
            }

            if (score > maxSimilarity) {
                maxSimilarity = score;
                detectedBrand = brand;
                detectedReason = reasons;
            }
        }

        // 4.Verdict
        if (maxSimilarity >= 60 && detectedBrand) {
            console.warn(`[Chameleon] 🦎 DNA MISMATCH! Page is ${detectedBrand} clone (${maxSimilarity}%) on ${currentHost}`);

            return {
                isClone: true,
                brand: detectedBrand,
                confidence: maxSimilarity,
                reasons: detectedReason
            };
        }

        return { isClone: false };
    },

    checkLogos: function (hints, htmlLower) {
        const hit = hints.some(hint => htmlLower.includes(hint));
        if (!hit) return false;
        const imgs = document.getElementsByTagName('img');
        for (let img of imgs) {
            const src = (img.src || '').toLowerCase();
            const alt = (img.alt || '').toLowerCase();
            const classList = (img.className || '').toLowerCase();
            if (hints.some(h => src.includes(h) || alt.includes(h) || classList.includes(h))) {
                return true;
            }
        }
        return true;
    }
};

if (typeof window !== 'undefined') {
    window.Chameleon = Chameleon;
}
