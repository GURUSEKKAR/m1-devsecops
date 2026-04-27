FROM node:18-alpine3.21 AS deps
RUN apk update && apk upgrade --no-cache && rm -rf /var/cache/apk/*
WORKDIR /app
COPY src/package.json ./
RUN npm install --omit=dev && npm cache clean --force

FROM node:18-alpine3.21
RUN apk update && apk upgrade --no-cache && rm -rf /var/cache/apk/*
RUN rm -rf \
    /usr/local/lib/node_modules/npm \
    /usr/local/lib/node_modules/corepack \
    /usr/local/bin/npm \
    /usr/local/bin/npx \
    /usr/local/bin/corepack \
    /opt/yarn-v1.22.22 \
    /usr/local/bin/yarn \
    /usr/local/bin/yarnpkg
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY src/ ./
RUN chown -R appuser:appgroup /app
USER appuser
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s \
    CMD wget -qO- http://localhost:8080/health || exit 1
CMD ["node", "index.js"]



# #testing -vul
# # ============================================================
# # M1 DevSecOps - Vulnerable Test Image
# # ============================================================
# # Base image is pinned to an OLD Node.js 14 release.
# # Trivy will find dozens of CRITICAL/HIGH OS package CVEs
# # (OpenSSL, glibc, libcurl, etc.) in this layer.
# # ============================================================

# FROM node:14.17.0

# # Set working directory
# WORKDIR /app

# # BAD: install global dev tools into the production image (bloat + extra CVEs)
# RUN apt-get update && apt-get install -y \
#     curl \
#     wget \
#     git \
#     && rm -rf /var/lib/apt/lists/*

# # Copy and install dependencies (old versions = more CVEs from OWASP DC)
# COPY src/package.json ./
# RUN npm install --no-audit --no-fund || true

# # Copy app source
# COPY src/ ./

# # BAD: running as root (Trivy / best-practice scanners flag this)
# # (We deliberately do NOT add a USER directive)

# EXPOSE 8080

# # Health check matches the /health endpoint Jenkins polls
# HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
#   CMD curl -f http://localhost:8080/health || exit 1

# CMD ["node", "index.js"]



# #------------3

# FROM node:14.17.0
# WORKDIR /app
# COPY src/package.json ./
# RUN npm install --no-audit --no-fund || true
# COPY src/ ./
# EXPOSE 8080
# HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
#   CMD curl -f http://localhost:8080/health || exit 1
# CMD ["node", "index.js"]