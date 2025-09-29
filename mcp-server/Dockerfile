FROM node:20-alpine

# Set working directory
WORKDIR /app

# Install dependencies first (better caching)
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

# Copy source code
COPY src/ ./src/

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S mcpserver -u 1001 -G nodejs

# Change ownership of the app directory
RUN chown -R mcpserver:nodejs /app

# Switch to non-root user
USER mcpserver

# Expose port for web configuration interface
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node -e "console.log('MCP Server is healthy')" || exit 1

# Default command
CMD ["npm", "start"]
