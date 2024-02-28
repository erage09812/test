# Use an official Python runtime as a parent image
FROM golang:1.22-alpine AS builder
ARG USERNAME
ARG PASSWORD
ARG SECURITY_TOKEN

ENV USERNAME=$Env:USERNAME
ENV PASSWORD=$Env:PASSWORD
ENV SECURITY_TOKEN=$Env:SECURITY_TOKEN
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
# Define any environment variables needed by your application
ARG USERNAME
ARG PASSWORD
ARG SECURITY_TOKEN

ENV USERNAME=$Env:USERNAME
ENV PASSWORD=$Env:PASSWORD
ENV SECURITY_TOKEN=$Env:SECURITY_TOKEN

# Copy the binary from the previous stage
COPY --from=builder /app/app .

# Set the user for the container (for security reasons)
USER 1000:1000

# Expose any necessary ports
EXPOSE 8080

# Run app.py when the container launches
CMD ["./app"]




