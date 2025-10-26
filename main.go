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

    var bodyBytes []byte
    if r.Body != nil && (r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH") {
        var err error
        bodyBytes, err = io.ReadAll(r.Body)
        if err != nil {
            jsonError(w, "Failed to read request body", http.StatusBadRequest)
            return
        }
        r.Body.Close()

        if len(bodyBytes) > 0 {
            var bodyData map[string]interface{}
            if err := json.Unmarshal(bodyBytes, &bodyData); err != nil {
                jsonError(w, "Invalid JSON in request body", http.StatusBadRequest)
                return
            }

            processSystemParam(bodyData)

            bodyBytes, _ = json.Marshal(bodyData)
        }
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

    var bodyBytes []byte
    if r.Body != nil && (r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH") {
        var err error
        bodyBytes, err = io.ReadAll(r.Body)
        if err != nil {
            jsonError(w, "Failed to read request body", http.StatusBadRequest)
            return
        }
        r.Body.Close()

        if len(bodyBytes) > 0 {
            var bodyData map[string]interface{}
            if err := json.Unmarshal(bodyBytes, &bodyData); err != nil {
                jsonError(w, "Invalid JSON in request body", http.StatusBadRequest)
                return
            }

            if model, ok := bodyData["model"].(string); ok && model == "gpt-5" {
                bodyData["model"] = "gpt-5-2025-08-07"
                log.Println("[Proxy] 模型 gpt-5 已替换为 gpt-5-2025-08-07")
            }

            if model, ok := bodyData["model"].(string); ok && model == "gpt-5-codex" {
                if reasoning, ok := bodyData["reasoning"].(map[string]interface{}); ok {
                    if _, hasEffort := reasoning["effort"]; hasEffort {
                        delete(reasoning, "effort")
                        log.Println("[Proxy] 已移除 gpt-5-codex 模型的 reasoning.effort 字段")
                    }
                }
            }

            bodyData["instructions"] = "You are Droid, an AI software engineering agent built by Factory.\n"

            bodyBytes, _ = json.Marshal(bodyData)
        }
    }

    proxyReq, err := http.NewRequest(r.Method, OPENAI_TARGET, bytes.NewReader(bodyBytes))
    if err != nil {
        jsonError(w, "Failed to create proxy request", http.StatusInternalServerError)
        return
    }

    copyHeaders(r, proxyReq)
    proxyReq.Header.Set("Host", proxyReq.URL.Host)

    log.Printf("[Proxy] 转发 OpenAI 请求到: %s", OPENAI_TARGET)
    forwardRequest(w, proxyReq)
}

func handleBedrockRequest(w http.ResponseWriter, r *http.Request) {
    bearerToken := extractBearerToken(r)
    if bearerToken == "" {
        jsonError(w, "x-api-key or Authorization Bearer token is required", http.StatusUnauthorized)
        return
    }

    var bodyBytes []byte
    if r.Body != nil && (r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH") {
        var err error
        bodyBytes, err = io.ReadAll(r.Body)
        if err != nil {
            jsonError(w, "Failed to read request body", http.StatusBadRequest)
            return
        }
        r.Body.Close()

        if len(bodyBytes) > 0 {
            var bodyData map[string]interface{}
            if err := json.Unmarshal(bodyBytes, &bodyData); err != nil {
                jsonError(w, "Invalid JSON in request body", http.StatusBadRequest)
                return
            }

            processSystemParam(bodyData)

            bodyBytes, _ = json.Marshal(bodyData)
        }
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

    log.Printf("[Proxy] 转发 Bedrock 请求到: %s", BEDROCK_TARGET)
    forwardRequest(w, proxyReq)
}

func extractBearerToken(r *http.Request) string {
    if apiKey := r.Header.Get("X-Api-Key"); apiKey != "" {
        return apiKey
    }
    authHeader := r.Header.Get("Authorization")
    if strings.HasPrefix(authHeader, "Bearer ") {
        return strings.TrimPrefix(authHeader, "Bearer ")
    }
    return ""
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
