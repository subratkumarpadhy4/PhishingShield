#!/bin/bash
echo "🛡️  Starting PhishingShield Ecosystem..."
echo "-------------------------------------"

# 1. Enter Server Directory
cd server

# 2. Check for dependencies & Install if missing
if [ ! -d "node_modules" ]; then
    echo "📦 Dependencies missing. Installing now..."
    echo "   (This may take a minute for the first run)"
    npm install
    echo "✅ Dependencies installed!"
fi

# 3. Wake up the Global Server (Cloud)
echo "🌍 Connecting to Global Cloud Server..."
status_code=$(curl --write-out %{http_code} --silent --output /dev/null https://phishingshield-ruby.vercel.app/api/reports)

if [[ "$status_code" -eq 200 ]] ; then
  echo "✅ Global Server is ONLINE and Ready."
else
  echo "⚠️  Global Server might be sleeping or unreachable (Status: $status_code). Trying to wake it up..."
  curl -s -o /dev/null https://phishingshield-ruby.vercel.app/api/reports
fi

# 4. Start the Local Server
echo "-------------------------------------"
echo "💻 Starting Local Server (localhost:3000)..."
echo "   All bans & XP will be synced to Global Cloud."
echo "-------------------------------------"

# Start Keep-Alive in background
echo "💓 Starting Global Keep-Alive Daemon..."
node keep-alive.js &

npm start
