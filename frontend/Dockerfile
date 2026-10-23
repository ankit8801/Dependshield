# Frontend Production Dockerfile
#
# Stage 1: Vite build
#   - Builds the React SPA into static files
#   - VITE_API_URL is passed at build-time so the frontend knows the backend URL
#
# Stage 2: Nginx runtime
#   - Serves the static build from nginx:alpine
#   - Configured for SPA routing (all 404s → index.html)
#   - API requests proxied to the backend service

# ─── Stage 1: Builder ───────────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .

# VITE_API_URL must be passed as a build arg so Vite can embed it at compile time.
# In docker-compose it is set via: build.args.VITE_API_URL
# Default points to localhost for standalone use.
ARG VITE_API_URL=http://localhost:3000/api/v1
ENV VITE_API_URL=$VITE_API_URL

RUN npm run build

# ─── Stage 2: Nginx production server ───────────────────────────────────────
FROM nginx:1.27-alpine AS production

# Remove default nginx config
RUN rm /etc/nginx/conf.d/default.conf

# Copy our SPA-aware nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy the built assets from the builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Nginx listens on port 80 inside the container
EXPOSE 80

# nginx -g 'daemon off;' keeps it in the foreground (required for Docker)
CMD ["nginx", "-g", "daemon off;"]
