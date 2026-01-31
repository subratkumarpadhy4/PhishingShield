const fs = require('fs');
const path = require('path');
// Node 18+ has native fetch, but we might be in an environment without it? 
// No, the user logic relies on it.

const REPORTS_FILE = path.join(__dirname, 'server', 'reports.json');
const GLOBAL_URL = 'https://phishingshield-ruby.vercel.app';

async function repair() {
    console.log("Starting Manual Repair...");

    if (!fs.existsSync(REPORTS_FILE)) {
        console.error("Reports file not found:", REPORTS_FILE);
        return;
    }

    const reports = JSON.parse(fs.readFileSync(REPORTS_FILE, 'utf8'));
    console.log(`Found ${reports.length} local reports.`);

    let success = 0;

    for (const report of reports) {
        try {
            console.log(`Uploading ${report.url} (${report.status})...`);

            // 1. Create Report (if new)
            await fetch(`${GLOBAL_URL}/api/reports`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(report)
            });

            // 2. Update Status (Force update)
            if (report.status !== 'pending') {
                await fetch(`${GLOBAL_URL}/api/reports/update`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ id: report.id, status: report.status })
                });
            }
            success++;
            console.log(" -> OK");
        } catch (error) {
            console.error(" -> FAILED:", error.message);
        }
    }

    console.log(`Repair Complete. Uploaded ${success}/${reports.length} reports.`);
}

repair();
