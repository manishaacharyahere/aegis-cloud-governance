# syntax=docker/dockerfile:1
# The dashboard for deployment: the built single-page app served by Caddy,
# which also proxies the API (same origin, so no CORS) and sets the security
# headers, including a Content-Security-Policy.

FROM node:24.22.1-alpine3.24 AS build
WORKDIR /web
COPY apps/web/package.json apps/web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY apps/web/ ./
RUN npm run build

FROM caddy:2.11.7-alpine
COPY infrastructure/web/Caddyfile /etc/caddy/Caddyfile
COPY --from=build /web/dist /srv
# Caddy keeps nothing needed across restarts here (no ACME: TLS ends at the
# ingress or load balancer), so its state lives in /tmp.
ENV XDG_DATA_HOME=/tmp/caddy-data XDG_CONFIG_HOME=/tmp/caddy-config \
    AEGIS_API_UPSTREAM=api:8080 AEGIS_CSP_CONNECT_SRC=""
USER 65532:65532
EXPOSE 8080
