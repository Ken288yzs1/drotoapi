# 第一阶段：构建
FROM golang:1.21-alpine AS builder

WORKDIR /app

# 复制 go.mod 和代码
COPY go.mod ./
COPY main.go .

# 下载依赖并构建
RUN go mod download && \
    CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-s -w" -o drotoapi main.go

# 第二阶段：运行
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /root/

COPY --from=builder /app/drotoapi .

EXPOSE 8000

CMD ["./drotoapi"]
