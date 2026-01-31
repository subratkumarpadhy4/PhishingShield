const http = require('http');
const https = require('https');

function fetchJson(url) {
    return new Promise((resolve, reject) => {
        const client = url.startsWith('https') ? https : http;
        const req = client.get(url, (res) => {
            if (res.statusCode < 200 || res.statusCode >= 300) {
                // Consume response data to free up memory
                res.resume();
                return reject(new Error(`Status Code: ${res.statusCode}`));
            }

            let data = '';
            res.on('data', (chunk) => { data += chunk; });
            res.on('end', () => {
                try {
                    resolve(JSON.parse(data));
                } catch (e) {
                    reject(e);
                }
            });
        });

        req.on('error', (e) => reject(e));
        req.end();
    });
}

async function verifySync() {
    const domain = 'example.com';
    const globalUrl = `https://oculus-eight.vercel.app/api/trust/score?domain=${domain}`;
    const localUrl = `http://localhost:3000/api/trust/score?domain=${domain}`;

    console.log(`[Verify] Checking Global Server: ${globalUrl}`);
    let globalData;
    try {
        globalData = await fetchJson(globalUrl);
        console.log('[Verify] Global Data:', globalData);
    } catch (e) {
        console.error('[Verify] Global Server Error:', e.message);
        return;
    }

    console.log(`[Verify] Checking Local Server: ${localUrl}`);
    let localData;
    try {
        localData = await fetchJson(localUrl);
        console.log('[Verify] Local Data:', localData);
    } catch (e) {
        console.error('[Verify] Local Server Error (Ensure "node server/server.js" is running):', e.message);
        return;
    }

    console.log('--------------------------------------------------');
    // Normalize for comparison
    const globalStr = JSON.stringify(globalData);
    const localStr = JSON.stringify(localData);

    if (globalStr === localStr) {
        console.log('✅ SUCCESS: Local Server correctly mirrors Global Server.');
    } else {
        console.log('❌ FAILURE: Data mismatch.');
        console.log('Expected:', globalData);
        console.log('Received:', localData);

        if (localData.score !== globalData.score) console.log(`   - Score mismatch: Global ${globalData.score} vs Local ${localData.score}`);
        if (localData.votes !== globalData.votes) console.log(`   - Votes mismatch: Global ${globalData.votes} vs Local ${localData.votes}`);
    }
}

verifySync();
