#!/bin/bash

# Create logs directory
mkdir -p /zap/server/logs

# Start ZAP daemon
echo "Starting ZAP daemon..."
zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.key=change-me-1234 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true &

# Wait for ZAP to start
echo "Waiting for ZAP to start..."
while ! curl --output /dev/null --silent --head --fail http://localhost:8080; do
  sleep 2
done

echo "ZAP is running!"

# Start Node.js server
echo "Starting MCP server..."
cd /zap/server
npm start
