ARG GO_VERSION=1.25
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS builder

WORKDIR /app

ARG TARGETOS
ARG TARGETARCH

COPY src/go.mod src/go.sum ./
RUN go mod download
COPY src/*.go ./

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -a -installsuffix cgo -ldflags="-w -s" -o signer ./

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /app/signer /signer
ENTRYPOINT ["/signer"]