### ---------- BUILDER ----------
FROM node:20.20-alpine3.23 AS builder

WORKDIR /app

RUN apk update && apk upgrade --no-cache

# Prisma needs DATABASE_URL at generate time
ARG DATABASE_URL=postgresql://user:pass@localhost:5432/db
ENV DATABASE_URL=$DATABASE_URL
ENV NEON_PG_DATABASE_URL=$DATABASE_URL

COPY package*.json ./
RUN npm install

COPY . .

RUN npm run build \
  && npm run prisma:generate \
  && npm run css:build

# Remove devDependencies
RUN npm prune --omit=dev

### ---------- RUNTIME ----------
FROM node:20.20-alpine3.23 

RUN apk update && apk upgrade --no-cache

# Non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

RUN mkdir -p dist public generated logs src \
  && chown -R appuser:appgroup /app

COPY --chown=appuser:appgroup --from=builder /app/package*.json ./
COPY --chown=appuser:appgroup --from=builder /app/node_modules ./node_modules
COPY --chown=appuser:appgroup --from=builder /app/dist ./dist
COPY --chown=appuser:appgroup --from=builder /app/public ./public
COPY --chown=appuser:appgroup --from=builder /app/generated ./generated
COPY --chown=appuser:appgroup --from=builder /app/src/views ./src/views

# REMOVE NPM FROM RUNTIME (major CVE reduction)
RUN npm uninstall -g npm && \
  rm -rf /usr/lib/node_modules/npm \
  /usr/local/lib/node_modules/npm \
  /usr/local/bin/npm \
  /usr/local/bin/npx

USER appuser

EXPOSE 8080
CMD ["node", "dist/index.js"]