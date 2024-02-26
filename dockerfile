FROM golang:1.22-alpine AS builder
WORKDIR /test
COPY go.mod go.sum ./test
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o app ./cmd/main.go

FROM gcr.io/distroless/static
COPY --from=builder /test /test .
# COPY --from=builder /app/config.toml .
USER 1000:1000
EXPOSE 8080
CMD ["./test"]
