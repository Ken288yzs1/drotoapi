FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY main.go .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-s -w" -o drotoapi main.go

FROM alpine:latest

WORKDIR /root/

COPY --from=builder /app/drotoapi .

EXPOSE 8000

CMD ["./drotoapi"]
