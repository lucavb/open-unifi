# Multi-stage build: console bundle (node), static controller binary
# (CGO off, trimpath, stripped), then a distroless nonroot runtime.

# The admin console is build output, never committed: produce the
# go:embed input here, mirroring `make update-frontend` (vite.config.js
# writes ../internal/adminapi/static/dist relative to web/).
FROM --platform=$BUILDPLATFORM node:24-alpine AS console
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build

ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Never embed a stale bundle from the build context: the console stage's
# build is the source of truth for what goes into the binary.
RUN rm -rf internal/adminapi/static/dist
COPY --from=console /src/internal/adminapi/static/dist ./internal/adminapi/static/dist
RUN mkdir -p /out/data
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/openunifi ./cmd/openunifi

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/openunifi /openunifi
# The JSON store lives in /data (devices.json, wireless.json,
# devices.json). Pre-create it nonroot-owned so a named volume
# initializes writable without a --user override; bind mounts need
# `chown 65532:65532` on the host side.
COPY --from=build --chown=65532:65532 /out/data /data
USER nonroot:nonroot
# Inform :8080/tcp, admin :8443/tcp, discovery :10001/udp.
EXPOSE 8080 8443 10001/udp
# Everything else is flag/env passthrough: OPEN_UNIFI_ADMIN_TOKEN is
# required (the startup admin check fails on an empty token unless
# --allow-anonymous-admin is passed), OPEN_UNIFI_DEVICE_SSH_KEY seeds the
# provisioned SSH public keys on first boot, and --controller-url must
# point back at this container's published :8080. Args after the image
# name are appended
# and may repeat any flag (last one wins).
ENTRYPOINT ["/openunifi", "--data-dir", "/data"]
