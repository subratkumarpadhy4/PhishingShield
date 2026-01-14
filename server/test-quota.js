const { GoogleGenerativeAI } = require("@google/generative-ai");
const path = require("path");
require('dotenv').config({ path: path.join(__dirname, '../.env') });

async function testCandidate(modelName) {
    console.log(`\n🧪 Testing model: ${modelName}`);
    const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
    const model = genAI.getGenerativeModel({ model: modelName });

    try {
        const result = await model.generateContent("Say hi");
        console.log(`✅ SUCCESS! ${modelName} works.`);
        return true;
    } catch (e) {
        if (e.message.includes("429")) {
            console.log(`⚠️  ${modelName} exists but Rate Limited (Status 429).`);
            // Check if limit is 0
            if (e.message.includes("limit: 0")) {
                console.log("   ❌ Limit is 0 (No Quota). Skipping.");
                return false;
            }
            return true; // It exists and we have quota (just temporally exhausted), so it's a valid choice
        }
        if (e.message.includes("404")) {
            console.log(`❌ ${modelName} NOT FOUND (Status 404).`);
            return false;
        }
        console.log(`❌ ${modelName} Failed:`, e.message);
        return false;
    }
}

async function findWorkingModel() {
    const candidates = [
        "gemini-2.0-flash-exp",
        "gemini-flash-latest",
        "gemini-pro-latest",
        "gemini-2.0-flash-lite-preview-02-05",
        "gemini-2.0-flash"
    ];

    for (const m of candidates) {
        if (await testCandidate(m)) {
            console.log(`\n🎉 Found working model: ${m}`);
            process.exit(0);
        }
    }
    console.log("\n❌ No working models found.");
    process.exit(1);
}

findWorkingModel();
