# Start from a base Go image with Go preinstalled
FROM golang:1.22-alpine AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy the Go module files
COPY go.mod sum.mod ./

# Download dependencies
RUN go mod download

# Copy the rest of the application source code
COPY . .

# Build the Go application with CGO disabled for a static binary
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/app ./cmd/main.go

# Start a new stage to create a minimal container
FROM gcr.io/distroless/static

# Set the working directory in the new stage
WORKDIR /app

# Copy the binary from the previous stage
COPY --from=builder /app/app .

# Set the user for the container (for security reasons)
USER 1000:1000

# Expose any necessary ports
EXPOSE 8080

# Command to run the application
CMD ["./app"]
