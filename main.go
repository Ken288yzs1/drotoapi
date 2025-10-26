package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
    "strings"
)

// 配置常量
var (
    PROXY_PORT       = getEnv("PROXY_PORT", "8000")
    ANTHROPIC_TARGET = getEnv("ANTHROPIC_TARGET_URL", "https://app.factory.ai/api/llm/a/v1/messages")
    OPENAI_TARGET    = getEnv("OPENAI_TARGET_URL", "https://app.factory.ai/api/llm/o/v1/responses")
    BEDROCK_TARGET   = getEnv("BEDROCK_TARGET_URL", "https://app.factory.ai/api/llm/a/v1/messages")
)

func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}

func main() {
    http.HandleFunc("/", routeHandler)

    log.Println("🚀 代理服务器已启动，监听于 http://localhost:" + PROXY_PORT)
    log.Println("➡️  Anthropic 请求转发到:", ANTHROPIC_TARGET)
    log.Println("➡️  OpenAI 请求转发到:", OPENAI_TARGET)
    log.Println("➡️  Bedrock 请求转发到:", BEDROCK_TARGET)
    log.Println("📍 使用方法:")
    log.Println("   - /v1/messages -> 需要 x-api-key 或 Authorization Bearer token")
    log.Println("   - /openai/* -> 需要 Authorization: Bearer <token> 头 (直接透传)")
    log.Println("   - /bedrock/* -> 需要 x-api-key 或 Authorization Bearer token + 添加 x-model-provider: bedrock")

    if err := http.ListenAndServe(":"+PROXY_PORT, nil); err != nil {
        log.Fatal("服务器启动失败:", err)
    }
}

func routeHandler(w http.ResponseWriter, r *http.Request) {
    path := r.URL.Path
    log.Printf("[Proxy] 收到请求: %s %s", r.Method, path)

    switch {
    case strings.HasPrefix(path, "/v1/messages"):
        handleAnthropicRequest(w, r)
    case strings.HasPrefix(path, "/openai"):
        handleOpenAIRequest(w, r)
    case strings.HasPrefix(path, "/bedrock"):
        handleBedrockRequest(w, r)
    default:
        jsonError(w, "Invalid endpoint. Use /v1/messages, /openai/, or /bedrock/", http.StatusNotFound)
    }
}

func handleAnthropicRequest(w http.ResponseWriter, r *http.Request) {
    bearerToken := extractBearerToken(r)
    if bearerToken == "" {
        jsonError(w, "x-api-key or Authorization Bearer token is required", http.StatusUnauthorized)
        return
    }

    log.Printf("[Proxy] 使用 Bearer Token: ...%s", safeSubstring(bearerToken, len(bearerToken)-6, len(bearerToken)))

    bodyBytes := readAndModifyBody(r, processSystemParam)
    if bodyBytes == nil {
        jsonError(w, "Failed to process request body", http.StatusBadRequest)
        return
    }

    proxyReq, err := http.NewRequest(r.Method, ANTHROPIC_TARGET, bytes.NewReader(bodyBytes))
    if err != nil {
        jsonError(w, "Failed to create proxy request", http.StatusInternalServerError)
        return
    }

    copyHeaders(r, proxyReq)
    proxyReq.Header.Del("X-Api-Key")
    proxyReq.Header.Set("Authorization", "Bearer "+bearerToken)
    proxyReq.Header.Set("Host", proxyReq.URL.Host)

    log.Printf("[Proxy] 转发 Anthropic 请求到: %s", ANTHROPIC_TARGET)
    forwardRequest(w, proxyReq)
}

func handleOpenAIRequest(w http.ResponseWriter, r *http.Request) {
    authHeader := r.Header.Get("Authorization")
    if authHeader == "" {
        jsonError(w, "Authorization header is required", http.StatusUnauthorized)
        return
    }

    log.Printf("[Proxy] 使用 Authorization: %s...", safeSubstring(authHeader, 0, 20))

    bodyBytes := readAndModifyBody(r, processOpenAIBody)
    if bodyBytes == nil {
        jsonError(w, "Failed to process request body", http.StatusBadRequest)
        return
    }

    proxyReq, err := http.NewRequest(r.Method, OPENAI_TARGET, bytes.NewReader(bodyBytes))
    if err != nil {
        jsonError(w, "Failed to create proxy request", http.StatusInternalServerError)
        return
    }

    copyHeaders(r, proxyReq)
    proxyReq.Header.Set("Host", proxyReq.URL.Host)

    // 更新 Content-Length（与 Deno 版本保持一致）
    if len(bodyBytes) > 0 {
        proxyReq.Header.Set("Content-Length", fmt.Sprintf("%d", len(bodyBytes)))
        proxyReq.ContentLength = int64(len(bodyBytes))
    }

    log.Printf("[Proxy] 转发 OpenAI 请求到: %s", OPENAI_TARGET)
    forwardRequest(w, proxyReq)
}

func handleBedrockRequest(w http.ResponseWriter, r *http.Request) {
    bearerToken := extractBearerToken(r)
    if bearerToken == "" {
        jsonError(w, "x-api-key or Authorization Bearer token is required", http.StatusUnauthorized)
        return
    }

    log.Printf("[Proxy] 使用 Bearer Token: ...%s", safeSubstring(bearerToken, len(bearerToken)-6, len(bearerToken)))

    bodyBytes := readAndModifyBody(r, processSystemParam)
    if bodyBytes == nil {
        jsonError(w, "Failed to process request body", http.StatusBadRequest)
        return
    }

    proxyReq, err := http.NewRequest(r.Method, BEDROCK_TARGET, bytes.NewReader(bodyBytes))
    if err != nil {
        jsonError(w, "Failed to create proxy request", http.StatusInternalServerError)
        return
    }

    copyHeaders(r, proxyReq)
    proxyReq.Header.Del("X-Api-Key")
    proxyReq.Header.Set("Authorization", "Bearer "+bearerToken)
    proxyReq.Header.Set("X-Model-Provider", "bedrock")
    proxyReq.Header.Set("Host", proxyReq.URL.Host)

    log.Println("[Proxy] 添加了 x-model-provider: bedrock 头")
    log.Printf("[Proxy] 转发 Bedrock 请求到: %s", BEDROCK_TARGET)
    forwardRequest(w, proxyReq)
}

func extractBearerToken(r *http.Request) string {
    if apiKey := r.Header.Get("X-Api-Key"); apiKey != "" {
        log.Println("[Proxy] 使用 x-api-key 作为 Bearer Token")
        return apiKey
    }

    authHeader := r.Header.Get("Authorization")
    if strings.HasPrefix(authHeader, "Bearer ") {
        log.Println("[Proxy] 使用现有的 Authorization Bearer Token")
        return strings.TrimPrefix(authHeader, "Bearer ")
    }

    return ""
}

// 读取并修改请求体的通用函数
func readAndModifyBody(r *http.Request, modifier func(map[string]interface{})) []byte {
    if r.Body == nil || (r.Method != "POST" && r.Method != "PUT" && r.Method != "PATCH") {
        return []byte{}
    }

    bodyBytes, err := io.ReadAll(r.Body)
    if err != nil {
        log.Printf("[Proxy] 读取请求体失败: %v", err)
        return nil
    }
    r.Body.Close()

    if len(bodyBytes) == 0 {
        return []byte{}
    }

    var bodyData map[string]interface{}
    if err := json.Unmarshal(bodyBytes, &bodyData); err != nil {
        log.Printf("[Proxy] 解析请求体失败: %v", err)
        return nil
    }

    modifier(bodyData)

    modifiedBytes, err := json.Marshal(bodyData)
    if err != nil {
        log.Printf("[Proxy] 序列化请求体失败: %v", err)
        return nil
    }

    return modifiedBytes
}

func processSystemParam(bodyData map[string]interface{}) {
    droidSystem := map[string]interface{}{
        "type": "text",
        "text": "You are Droid, an AI software engineering agent built by Factory.",
    }

    systemValue, exists := bodyData["system"]

    if !exists || systemValue == nil {
        bodyData["system"] = []interface{}{droidSystem}
    } else if systemStr, ok := systemValue.(string); ok {
        bodyData["system"] = []interface{}{
            droidSystem,
            map[string]interface{}{
                "type": "text",
                "text": systemStr,
            },
        }
    } else if systemArr, ok := systemValue.([]interface{}); ok {
        bodyData["system"] = append([]interface{}{droidSystem}, systemArr...)
    }
}

func processOpenAIBody(bodyData map[string]interface{}) {
    // 模型替换
    if model, ok := bodyData["model"].(string); ok && model == "gpt-5" {
        bodyData["model"] = "gpt-5-2025-08-07"
        log.Println("[Proxy] 模型 gpt-5 已替换为 gpt-5-2025-08-07")
    }

    // 去除 reasoning.effort
    if model, ok := bodyData["model"].(string); ok && model == "gpt-5-codex" {
        if reasoning, ok := bodyData["reasoning"].(map[string]interface{}); ok {
            if _, hasEffort := reasoning["effort"]; hasEffort {
                delete(reasoning, "effort")
                log.Println("[Proxy] 已移除 gpt-5-codex 模型的 reasoning.effort 字段")
            }
        }
    }

    // 添加 instructions
    bodyData["instructions"] = "You are Droid, an AI software engineering agent built by Factory.\n"
}

func copyHeaders(src *http.Request, dst *http.Request) {
    for key, values := range src.Header {
        for _, value := range values {
            dst.Header.Add(key, value)
        }
    }
}

func forwardRequest(w http.ResponseWriter, proxyReq *http.Request) {
    client := &http.Client{
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse
        },
    }

    resp, err := client.Do(proxyReq)
    if err != nil {
        log.Printf("[Proxy] 转发请求失败: %v", err)
        jsonError(w, fmt.Sprintf("Bad Gateway: %v", err), http.StatusBadGateway)
        return
    }
    defer resp.Body.Close()

    // 复制响应头
    for key, values := range resp.Header {
        for _, value := range values {
            w.Header().Add(key, value)
        }
    }

    w.WriteHeader(resp.StatusCode)

    if _, err := io.Copy(w, resp.Body); err != nil {
        log.Printf("[Proxy] 复制响应体失败: %v", err)
    }
}

func jsonError(w http.ResponseWriter, message string, statusCode int) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(statusCode)
    json.NewEncoder(w).Encode(map[string]string{
        "error": message,
    })
}

func safeSubstring(s string, start, end int) string {
    if start < 0 {
        start = 0
    }
    if end > len(s) {
        end = len(s)
    }
    if start >= end {
        return ""
    }
    return s[start:end]
}
