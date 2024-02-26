# Use an official Python runtime as a parent image
FROM python:3.8-slim
FROM golang:1.22-alpine AS builder

# Set the working directory in the container
WORKDIR /test

# Copy the current directory contents into the container at /app
COPY . /test


# Install any needed dependencies specified in requirements.txt
#RUN pip install --no-cache-dir -r requirements.txt
RUN CGO_ENABLED=0 GOOS=linux go build -o /test/main ./cmd/main.go

# Make port 80 available to the world outside this container
EXPOSE 80
EXPOSE 8080

# Define environment variable
ENV NAME World

FROM gcr.io/distroless/static
COPY . /test
# Run app.py when the container launches
CMD ["python", "app.py"]
