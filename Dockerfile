FROM owasp/zap2docker-stable:latest

# Install additional dependencies
USER root
RUN apt-get update && apt-get install -y \
    curl \
    git \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Set up working directory
WORKDIR /zap/server

# Copy server files
COPY server.js /zap/server/
COPY config.json /zap/server/
COPY package.json /zap/server/

# Install Node.js dependencies
RUN npm install

# Create directory for scan results
RUN mkdir -p /zap/reports

# Add script to start ZAP and server
COPY start.sh /zap/
RUN chmod +x /zap/start.sh

# Switch back to zap user
USER zap

# Expose ports
EXPOSE 8080 8090

# Start script
ENTRYPOINT ["/zap/start.sh"]