# ============================================
# Stage 1: Build React UI
# ============================================
FROM --platform=$BUILDPLATFORM node:26-alpine AS ui-builder

WORKDIR /app/ui
COPY ui/package*.json ./
RUN npm ci --production=false
COPY ui/ .
RUN npm run build

# ============================================
# Stage 2: Build Go backend
# ============================================
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS go-builder

# Release builds pass the tag so `orbit version` reports it.
ARG VERSION=dev
# Set by BuildKit; defaults keep a plain amd64 build working.
ARG TARGETOS=linux
ARG TARGETARCH=amd64

RUN apk add --no-cache git

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Embed the UI dist into the binary's working dir
COPY --from=ui-builder /app/ui/dist ./ui/dist

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w -X github.com/aligoren/orbit/internal/buildinfo.Version=${VERSION}" -o /orbit ./cmd/orbit

# ============================================
# Stage 3: Production runtime
# ============================================
FROM alpine:3.24

RUN apk add --no-cache ca-certificates git tzdata

RUN adduser -D -u 10001 -g '' orbit
WORKDIR /home/orbit

COPY --from=go-builder --chown=orbit:orbit /orbit .
COPY --from=go-builder --chown=orbit:orbit /app/orbit.yaml .
COPY --from=go-builder --chown=orbit:orbit /app/ui/dist ./ui/dist
COPY --from=go-builder --chown=orbit:orbit /app/internal/adapter/persistence/postgres/migrations ./migrations

USER 10001

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -qO- http://localhost:8080/api/v1/health || exit 1

ENTRYPOINT ["./orbit"]
