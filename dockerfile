# Use an official Python runtime as a parent image
FROM golang:1.22-alpine AS builder

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app
RUN go mod init erage09812/test
RUN go mod download
# Build the Go application with CGO disabled for a static binary
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/app ./login.go

FROM gcr.io/distroless/static
# Start a new stage to create a minimal container


# Copy the binary from the previous stage
COPY --from=builder /app/app .

# Set the user for the container (for security reasons)
USER 1000:1000

# Expose any necessary ports
EXPOSE 8080

# Run app.py when the container launches
CMD ["login.go"]

ENV SF_USERNAME='shvmkmr9120-jttd@force.com'
ENV SF_PASSWORD='test123!@#'
ENV SF_SECURITY_TOKEN='spfaS9BaktK2sHYWIvZJtKZBi'



