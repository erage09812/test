
# Use an official Python runtime as a parent image
FROM golang:1.22-alpine AS builder

# Set the working directory in the container
WORKDIR /

# Copy the current directory contents into the container at /app


# Install any needed dependencies specified in requirements.txt
RUN CGO_ENABLED=0 GOOS=linux go build -o /test/main ./cmd/main.go

# Make port 80 available to the world outside this container
EXPOSE 8080

# Define environment variable
FROM gcr.io/distroless/static
COPY . /
# Run app.py when the container launches
CMD ["python", "app.py"]
