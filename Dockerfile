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
