// Simple keep-alive script - run this locally while testing
const https = require('https');

const PING_URL = 'https://phishingshield-ruby.vercel.app/api/users';
const INTERVAL = 10 * 60 * 1000; // Ping every 10 minutes

console.log('🔄 Starting keep-alive service...');
console.log(`📡 Pinging ${PING_URL} every 10 minutes`);

function ping() {
    const start = Date.now();
    https.get(PING_URL, (res) => {
        const duration = Date.now() - start;
        console.log(`✅ Ping successful (${duration}ms) - Server is awake`);
    }).on('error', (err) => {
        console.error('❌ Ping failed:', err.message);
    });
}

// Ping immediately
ping();

// Then ping every 10 minutes
setInterval(ping, INTERVAL);

console.log('✨ Keep-alive service running. Press Ctrl+C to stop.');
