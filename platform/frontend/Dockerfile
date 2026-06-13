# --- Etapa 1: dependencias ---
FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
# Instala dependencias de forma reproducible. Si no hay lockfile, usa install.
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

# --- Etapa 2: build ---
FROM node:20-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# NEXT_PUBLIC_API_BASE se inyecta en build-time (puede sobreescribirse al construir).
ARG NEXT_PUBLIC_API_BASE=/api
ENV NEXT_PUBLIC_API_BASE=$NEXT_PUBLIC_API_BASE
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

# --- Etapa 3: runtime ---
FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

# Usuario no-root.
RUN addgroup -g 1001 -S nodejs && adduser -S nextjs -u 1001

# Copia la salida standalone (incluye node_modules minimos + server.js).
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs
EXPOSE 3000

# server.js es generado por output:'standalone'. Equivale a `next start` en :3000.
CMD ["node", "server.js"]
