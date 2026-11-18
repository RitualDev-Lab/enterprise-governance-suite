# Multi-stage hardened container for RitualDev Agent Defense Hub (Self-Hostable Enterprise Control Plane)
FROM node:22-alpine AS builder
WORKDIR /app

COPY package.json pnpm-lock.yaml tsconfig.json ./
RUN corepack enable && pnpm install --frozen-lockfile=false
COPY fleet ./fleet
RUN npx tsc --outDir dist --module commonjs --moduleResolution node --target ES2022 --esModuleInterop --skipLibCheck fleet/src/*.ts

FROM node:22-alpine AS runtime
LABEL org.opencontainers.image.title="RitualDev Agent Defense Hub"
LABEL org.opencontainers.image.description="Self-hostable Enterprise Control Plane: OIDC/SAML SSO, 3-Role RBAC Ed25519 Policy Signing, SkillPrism Redis Orchestration & CEF SIEM"
LABEL org.opencontainers.image.source="https://github.com/RitualDev-Lab/enterprise-governance-suite"
LABEL org.opencontainers.image.licenses="Apache-2.0"

RUN addgroup -g 10001 ritual && adduser -u 10001 -G ritual -D -H ritual
WORKDIR /app
COPY --from=builder --chown=10001:10001 /app/dist ./dist
COPY --from=builder --chown=10001:10001 /app/package.json ./package.json

USER 10001:10001
ENV NODE_ENV=production \
    HUB_HOST=0.0.0.0 \
    HUB_PORT=8443

EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8443/healthz || exit 1

CMD ["node", "dist/hub-cli.js"]
