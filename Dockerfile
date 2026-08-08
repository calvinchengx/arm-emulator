# Build: pure Go (modernc sqlite, no CGO) → distroless static.
FROM golang:1.25 AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /arm-emulator ./cmd/arm-emulator

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /arm-emulator /usr/local/bin/arm-emulator
ENV KV_DATA_DIR=/data
VOLUME /data
EXPOSE 8445
# Distroless has no shell; the binary probes its own /health.
HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD ["/usr/local/bin/arm-emulator", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/arm-emulator"]
