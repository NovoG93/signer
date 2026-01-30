# Builder stage
ARG AARCH=amd64
FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY src/go.mod src/go.sum ./
RUN go mod download
COPY src/*.go ./

RUN CGO_ENABLED=0 GOOS=linux GOARCH=${AARCH} go build -a -installsuffix cgo -ldflags="-w -s" -o signer ./

# Runtime stage
FROM gcr.io/distroless/static:nonroot
COPY --from=builder /app/signer /signer
ENTRYPOINT ["/signer"]