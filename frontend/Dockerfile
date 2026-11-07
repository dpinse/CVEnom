# syntax=docker/dockerfile:1
FROM node:26.13.0-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
# sourcemap is false in vite.config.ts: no .map files reach the image
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.30.6-alpine-slim
# Alpine security fixes land before the next base-image rebuild; take them now, then drop back
# to the unprivileged nginx user.
USER root
RUN apk upgrade --no-cache
USER 101
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
USER 101
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
