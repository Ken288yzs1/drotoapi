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

WORKDIR /root/

# 从构建阶段复制二进制文件
COPY --from=builder /app/drotoapi .

# 暴露端口
EXPOSE 8000

# 运行
CMD ["./drotoapi"]
