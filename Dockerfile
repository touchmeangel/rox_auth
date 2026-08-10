FROM --platform=$BUILDPLATFORM golang:1.26.5-bookworm AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 \
    GOOS=$TARGETOS \
    GOARCH=$TARGETARCH \
    go build \
      -trimpath \
      -ldflags="-s -w" \
      -o /out/rox_auth \
      ./cmd/rox_auth


FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

COPY --from=builder /out/rox_auth /usr/local/bin/rox_auth

ENTRYPOINT ["/usr/local/bin/rox_auth"]