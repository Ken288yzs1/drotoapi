# 第一阶段：构建
FROM golang:1.21-alpine AS builder

WORKDIR /app

# 复制 Go 代码
COPY main.go .

# 初始化 Go 模块并构建
RUN go mod init drotoapi && \
    go mod tidy && \
    CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-s -w" -o drotoapi main.go

# 第二阶段：运行
FROM alpine:latest

# 安装 CA 证书（用于 HTTPS 请求）
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /root/

# 从构建阶段复制二进制文件
COPY --from=builder /app/drotoapi .

# 暴露端口
EXPOSE 8000

# 运行
CMD ["./drotoapi"]
