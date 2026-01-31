const GLOBAL_URL = 'https://phishingshield-ruby.vercel.app';

async function verifyUnban() {
    console.log("1. Fetching Global Reports...");
    const res = await fetch(`${GLOBAL_URL}/api/reports`);
    const reports = await res.json();

    // Find a Banned report to test on, or create one
    let target = reports.find(r => r.status === 'banned');

    if (!target) {
        console.log("No banned reports found. Creating a test ban...");
        const testId = 'test-' + Date.now();
        const testReport = {
            id: testId,
            url: 'http://test-unban-' + Date.now() + '.com',
            status: 'banned',
            timestamp: Date.now(),
            lastUpdated: Date.now(),
            bannedAt: Date.now()
        };
        await fetch(`${GLOBAL_URL}/api/reports`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(testReport)
        });
        target = testReport;
        console.log("Created test ban:", target.url);
    } else {
        console.log("Found existing ban:", target.url, target.id);
    }

    console.log("2. Sending UNBAN (Pending) update...");
    const unbanRes = await fetch(`${GLOBAL_URL}/api/reports/update`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: target.id, status: 'pending' })
    });
    console.log("Update status:", unbanRes.status);

    console.log("3. verifying persistence...");
    const checkRes = await fetch(`${GLOBAL_URL}/api/reports`);
    const checkReports = await checkRes.json();
    const checked = checkReports.find(r => r.id === target.id);

    if (checked) {
        console.log(`Final Status: ${checked.status}`);
        if (checked.status === 'pending') {
            console.log("SUCCESS: Unban persisted.");
        } else {
            console.error("FAILURE: Unban reverted or ignored. Status is:", checked.status);
            console.log("Server Record:", checked);
        }
    } else {
        console.error("FAILURE: Report vanished.");
    }
}

verifyUnban();
