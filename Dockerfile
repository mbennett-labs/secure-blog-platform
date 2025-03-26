# Multi-stage build for optimized production image

# --- Build Stage ---
FROM node:18-alpine AS builder

# Set working directory
WORKDIR /app

# Install dependencies
COPY package.json package-lock.json ./
RUN npm ci

# Copy source code
COPY . .

# Generate Prisma client
RUN npx prisma generate

# Build application
RUN npm run build

# --- Production Stage ---
FROM node:18-alpine AS runner

# Set working directory
WORKDIR /app

# Create non-root user for security
RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 bloguser

# Set environment to production
ENV NODE_ENV production

# Copy only necessary files from build stage
COPY --from=builder --chown=bloguser:nodejs /app/package.json /app/package-lock.json ./
COPY --from=builder --chown=bloguser:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=bloguser:nodejs /app/.next ./.next
COPY --from=builder --chown=bloguser:nodejs /app/public ./public
COPY --from=builder --chown=bloguser:nodejs /app/prisma ./prisma
COPY --from=builder --chown=bloguser:nodejs /app/next.config.js ./

# Set permissions
RUN chmod -R 550 /app && \
    chmod -R 770 /app/node_modules /app/.next

# Switch to non-root user
USER bloguser

# Expose port
EXPOSE 3000

# Start the application
CMD ["npm", "start"]
