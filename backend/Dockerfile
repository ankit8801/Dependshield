# Backend Production Dockerfile
#
# Stage 1: Install dependencies (includes devDependencies for prisma generate)
# Stage 2: Production image — only production node_modules + generated client
#
# Security:
#   - Uses node:20-alpine (minimal attack surface)
#   - Runs as non-root user "node" (uid 1000)
#   - No build secrets embedded
#   - NODE_ENV=production suppresses devDependencies at runtime

# ─── Stage 1: Builder ───────────────────────────────────────────────────────
FROM node:20-bullseye-slim AS builder

WORKDIR /app

# Copy only manifest files first to leverage Docker layer cache
COPY package.json package-lock.json ./
COPY prisma ./prisma

# Install ALL deps (prisma CLI is a devDependency, needed for generate)
RUN npm ci

# Generate the Prisma client against the schema
RUN npx prisma generate

# ─── Stage 2: Production runtime ────────────────────────────────────────────
FROM node:20-bullseye-slim AS production

# Security: set NODE_ENV before npm ci so devDeps are excluded
ENV NODE_ENV=production
ENV PORT=3000

WORKDIR /app

# Create a non-root user to run the application
# node user already exists in the base image (uid=1000)

# Copy production manifests
COPY package.json package-lock.json ./

# Install only production dependencies
RUN npm ci --omit=dev

# Copy the generated Prisma client from the builder stage
COPY --from=builder /app/node_modules/.prisma ./node_modules/.prisma
COPY --from=builder /app/node_modules/@prisma/client ./node_modules/@prisma/client

# Copy Prisma schema (needed by @prisma/client at runtime)
COPY prisma ./prisma

# Copy application source
COPY src ./src
COPY server.js ./

# Create uploads directory with correct ownership before switching user
# The uploads dir is for temporary ZIP files; scans clean up after themselves
RUN mkdir -p uploads && chown -R node:node /app

# Switch to non-root user
USER node

EXPOSE 3000

# Use node directly (not npm start) for faster startup and proper signal handling
CMD ["node", "server.js"]
