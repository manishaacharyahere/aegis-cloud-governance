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
# The official binary carries the cap_net_bind_service file capability, and
# the kernel refuses to exec it in a container that drops all capabilities
# (as the Helm chart does). Port 8080 needs none: a plain copy has no file
# capabilities.
RUN cp /usr/bin/caddy /usr/bin/caddy.tmp && mv /usr/bin/caddy.tmp /usr/bin/caddy
COPY infrastructure/web/Caddyfile /etc/caddy/Caddyfile
COPY --from=build /web/dist /srv
# Caddy keeps nothing needed across restarts here (no ACME: TLS ends at the
# ingress or load balancer), so its state lives in /tmp.
ENV XDG_DATA_HOME=/tmp/caddy-data XDG_CONFIG_HOME=/tmp/caddy-config \
    AEGIS_API_UPSTREAM=api:8080 AEGIS_CSP_CONNECT_SRC=""
USER 65532:65532
EXPOSE 8080
