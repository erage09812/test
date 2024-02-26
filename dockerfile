# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build the Go application
RUN CGO_ENABLED=0 GOOS=linux go build -o /test/main ./cmd/main.go

# Final stage
FROM gcr.io/distroless/static

WORKDIR /

COPY --from=builder /test /test

# Optionally copy other necessary files (e.g., config files)
# COPY --from=builder /app/config.toml /test/config.toml

# Set the user for the container (for security reasons)
USER 1000:1000

# Expose any necessary ports
EXPOSE 8080

# Command to run the application
CMD ["/test"]
