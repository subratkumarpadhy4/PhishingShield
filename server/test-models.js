const { GoogleGenerativeAI } = require("@google/generative-ai");
const path = require("path");
require('dotenv').config({ path: path.join(__dirname, '../.env') });

async function listModels() {
    const key = process.env.GEMINI_API_KEY;
    if (!key) {
        console.error("❌ No GEMINI_API_KEY found in environment!");
        return;
    }
    console.log("🔑 API Key found (starts with):", key.substring(0, 5) + "...");

    const genAI = new GoogleGenerativeAI(key);

    try {
        // We can access the model manager via the class if the SDK supports it, 
        // but typically currently in node it's not directly exposed in the main helper 
        // same way as Python.
        // However, we can try to inspect a specific model or just try 'gemini-pro' which is the GA model.

        // Actually, the JS SDK doesn't have a simple listModels() helper on the top level client 
        // like the Python one does in some versions.
        // But let's try to verify if 'gemini-pro' works, as that is the stable GA model.

        console.log("🔄 Testing 'gemini-2.0-flash'...");
        const model = genAI.getGenerativeModel({ model: "gemini-2.0-flash" });
        const result = await model.generateContent("Hello");
        console.log("✅ 'gemini-pro' worked! Response:", result.response.text());

        console.log("🔄 Testing 'gemini-1.0-pro'...");
        const model2 = genAI.getGenerativeModel({ model: "gemini-1.0-pro" });
        const result2 = await model2.generateContent("Hello");
        console.log("✅ 'gemini-1.0-pro' worked!");

    } catch (error) {
        console.error("❌ Error listing/testing models:", error);
    }
}

listModels();
