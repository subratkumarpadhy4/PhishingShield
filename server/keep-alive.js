// Native fetch is used (Node 18+)

const GLOBAL_URL = 'https://phishingshield-ruby.vercel.app/api/reports';
const INTERVAL_MS = 14 * 60 * 1000; // 14 minutes (Render sleeps after 15)

console.log(`[Keep-Alive] Starting heartbeat for ${GLOBAL_URL}`);
console.log(`[Keep-Alive] Interval: ${INTERVAL_MS / 1000 / 60} minutes`);

function ping() {
    console.log(`[Keep-Alive] 💓 Pinging Global Server at ${new Date().toISOString()}...`);
    fetch(GLOBAL_URL)
        .then(res => {
            console.log(`[Keep-Alive] ✅ Alive! Status: ${res.status}`);
        })
        .catch(err => {
            
            console.error(`[Keep-Alive] ⚠️ Ping Failed: ${err.message}`);
        });
}

// Initial Ping
ping();

// Schedule
setInterval(ping, INTERVAL_MS);
