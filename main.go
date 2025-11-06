package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "math/rand"
    "net/http"
    "net/url"
    "os"
    "strings"
    "sync"
    "time"

    "golang.org/x/net/proxy"
)

// 全局配置
var (
    PROXY_PORT            = getEnv("PROXY_PORT", "8000")
    ANTHROPIC_TARGET      = getEnv("ANTHROPIC_TARGET_URL", "https://app.factory.ai/api/llm/a/v1/messages")
    OPENAI_TARGET         = getEnv("OPENAI_TARGET_URL", "https://app.factory.ai/api/llm/o/v1/responses")
    BEDROCK_TARGET        = getEnv("BEDROCK_TARGET_URL", "https://app.factory.ai/api/llm/a/v1/messages")
    FACTORY_KEYS_RAW      = getEnv("FACTORY_KEYS", "")
    SOCKS5_PROXY_TEMPLATE = getEnv("SOCKS5_PROXY_TEMPLATE", "")
)

// 全局 SID 池
var (
    sidPool  []string
    sidMutex sync.Mutex
)

// 全局状态
type ProxyState struct {
    batches         [][]string       // Key 分批
    batchClients    [][]*http.Client // 每批对应的 HTTP Client
    batchAvailable  [][]bool         // 每批 Key 的可用状态
    currentBatchIdx int              // 当前使用的批次索引
    currentKeyIdx   int              // 当前批次内的 Key 索引
    mu              sync.RWMutex     // 并发控制锁
    totalExhausted  bool             // 所有 Key 是否耗尽
}

var state *ProxyState

func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}

// 初始化 SID 池（保证唯一性）
func initSIDPool(size int) {
    log.Printf("🔢 开始生成 %d 个唯一的 SID...", size)

    sidPool = make([]string, size)
    usedSIDs := make(map[string]bool)

    for i := 0; i < size; i++ {
        for {
            // 生成随机 8 位数字
            sid := fmt.Sprintf("%08d", rand.Intn(90000000)+10000000)

            // 检查是否重复
            if !usedSIDs[sid] {
                sidPool[i] = sid
                usedSIDs[sid] = true
                break
            }
        }
    }

    log.Printf("✅ 成功生成 %d 个唯一的 SID", size)
}

// 从池中获取 SID
func getSIDFromPool(index int) string {
    sidMutex.Lock()
    defer sidMutex.Unlock()

    if index < 0 || index >= len(sidPool) {
        log.Printf("⚠️  警告: SID 索引越界: %d", index)
        return fmt.Sprintf("%08d", rand.Intn(90000000)+10000000)
    }

    return sidPool[index]
}

// 初始化 ProxyState
func initProxyState() {
    if FACTORY_KEYS_RAW == "" {
        log.Fatal("❌ 环境变量 FACTORY_KEYS 未设置")
    }

    if SOCKS5_PROXY_TEMPLATE == "" {
        log.Fatal("❌ 环境变量 SOCKS5_PROXY_TEMPLATE 未设置")
    }

    // 解析 Keys
    keys := strings.Split(FACTORY_KEYS_RAW, ",")
    for i := range keys {
        keys[i] = strings.TrimSpace(keys[i])
    }

    if len(keys) == 0 {
        log.Fatal("❌ FACTORY_KEYS 为空")
    }

    log.Printf("📊 加载了 %d 个 Factory Keys", len(keys))

    // 初始化 SID 池（生成唯一的 SID）
    initSIDPool(len(keys))

    // 分批（每批 5 个）
    batchSize := 5
    batches := [][]string{}
    for i := 0; i < len(keys); i += batchSize {
        end := i + batchSize
        if end > len(keys) {
            end = len(keys)
        }
        batches = append(batches, keys[i:end])
    }

    log.Printf("📦 分为 %d 批", len(batches))

    // 为每批创建 HTTP Clients
    batchClients := make([][]*http.Client, len(batches))
    batchAvailable := make([][]bool, len(batches))

    sidIndex := 0 // 全局 SID 索引

    for batchIdx, batch := range batches {
        log.Printf("📦 批次 %d: %d 个 Keys", batchIdx, len(batch))

        clients := make([]*http.Client, len(batch))
        available := make([]bool, len(batch))

        for keyIdx := range batch {
            // 从 SID 池获取唯一的 SID
            sid := getSIDFromPool(sidIndex)
            sidIndex++

            // 构建代理 URL
            proxyURL := strings.Replace(SOCKS5_PROXY_TEMPLATE, "%s", sid, 1)

            // 创建 HTTP Client
            client, err := createHTTPClient(proxyURL)
            if err != nil {
                log.Printf("⚠️  批次 %d, Key %d 创建 Client 失败: %v", batchIdx, keyIdx, err)
                clients[keyIdx] = nil
                available[keyIdx] = false
            } else {
                clients[keyIdx] = client
                available[keyIdx] = true
                log.Printf("   ✅ Key %d: sid_%s", keyIdx, sid)
            }
        }

        batchClients[batchIdx] = clients
        batchAvailable[batchIdx] = available
    }

    // 初始化全局状态
    state = &ProxyState{
        batches:         batches,
        batchClients:    batchClients,
        batchAvailable:  batchAvailable,
        currentBatchIdx: 0,
        currentKeyIdx:   0,
        totalExhausted:  false,
    }

    log.Println("✅ ProxyState 初始化完成")
}

// 创建 HTTP Client（带 SOCKS5 代理）
func createHTTPClient(proxyURL string) (*http.Client, error) {
    parsedURL, err := url.Parse(proxyURL)
    if err != nil {
        return nil, fmt.Errorf("解析代理 URL 失败: %v", err)
    }

    // 创建 SOCKS5 dialer
    var auth *proxy.Auth
    if parsedURL.User != nil {
        password, _ := parsedURL.User.Password()
        auth = &proxy.Auth{
            User:     parsedURL.User.Username(),
            Password: password,
        }
    }

    dialer, err := proxy.SOCKS5("tcp", parsedURL.Host, auth, proxy.Direct)
    if err != nil {
        return nil, fmt.Errorf("创建 SOCKS5 dialer 失败: %v", err)
    }

    // 创建 Transport
    transport := &http.Transport{
        Dial:                dialer.Dial,
        MaxIdleConns:        500,
        MaxIdleConnsPerHost: 100,
        MaxConnsPerHost:     0,
    }

    // 创建 Client
    client := &http.Client{
        Transport: transport,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse
        },
    }

    return client, nil
}

// 选择下一个可用的 Key
func selectNextAvailableKey() (batchIdx int, keyIdx int, client *http.Client, factoryKey string) {
    state.mu.Lock()
    defer state.mu.Unlock()

    // 检查是否完全耗尽
    if state.totalExhausted {
        return -1, -1, nil, ""
    }

    // 从当前批次开始查找
    startBatchIdx := state.currentBatchIdx

    for {
        batch := state.batches[state.currentBatchIdx]
        available := state.batchAvailable[state.currentBatchIdx]
        clients := state.batchClients[state.currentBatchIdx]

        // 在当前批次中查找可用 Key
        found := false
        startKeyIdx := state.currentKeyIdx

        for i := 0; i < len(batch); i++ {
            idx := (startKeyIdx + i) % len(batch)

            if available[idx] {
                // 找到可用 Key
                state.currentKeyIdx = (idx + 1) % len(batch)

                return state.currentBatchIdx, idx, clients[idx], batch[idx]
            }
        }

        // 当前批次全部不可用，切换到下一批
        if !found {
            log.Printf("⚠️  批次 %d 全部耗尽，尝试切换到下一批", state.currentBatchIdx)

            state.currentBatchIdx++
            state.currentKeyIdx = 0

            // 检查是否还有下一批
            if state.currentBatchIdx >= len(state.batches) {
                // 所有批次都耗尽
                log.Println("❌ 所有 API Keys 已耗尽")
                state.totalExhausted = true
                return -1, -1, nil, ""
            }

            log.Printf("📦 切换到批次 %d", state.currentBatchIdx)

            // 检查是否回到起始批次（避免死循环）
            if state.currentBatchIdx == startBatchIdx {
                state.totalExhausted = true
                return -1, -1, nil, ""
            }
        }
    }
}

// 标记 Key 为耗尽
func markKeyAsExhausted(batchIdx, keyIdx int) {
    state.mu.Lock()
    defer state.mu.Unlock()

    state.batchAvailable[batchIdx][keyIdx] = false
    log.Printf("⚠️  Key 已耗尽: 批次 %d, 索引 %d", batchIdx, keyIdx)

    // 检查当前批次是否全部耗尽
    allExhausted := true
    for _, avail := range state.batchAvailable[batchIdx] {
        if avail {
            allExhausted = false
            break
        }
    }

    if allExhausted {
        log.Printf("⚠️  批次 %d 全部耗尽", batchIdx)
    }
}

func main() {
    // 初始化随机数生成器（只执行一次）
    rand.Seed(time.Now().UnixNano())

    // 初始化状态
    initProxyState()

    // 设置路由
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
    // 选择可用 Key
    batchIdx, keyIdx, client, factoryKey := selectNextAvailableKey()
    if client == nil {
        jsonError(w, "API key pool exhausted", http.StatusNotImplemented) // 501
        return
    }

    log.Printf("[Proxy] 使用批次 %d, Key 索引 %d", batchIdx, keyIdx)

    // 读取并修改请求体
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

    // 创建转发请求
    proxyReq, err := http.NewRequest(r.Method, ANTHROPIC_TARGET, bytes.NewReader(bodyBytes))
    if err != nil {
        jsonError(w, "Failed to create proxy request", http.StatusInternalServerError)
        return
    }

    // 复制请求头
    copyHeaders(r, proxyReq)

    // 删除用户的认证头，使用号池 Key
    proxyReq.Header.Del("X-Api-Key")
    proxyReq.Header.Del("Authorization")
    proxyReq.Header.Set("Authorization", "Bearer "+factoryKey)
    proxyReq.Header.Set("Host", proxyReq.URL.Host)

    log.Printf("[Proxy] 转发 Anthropic 请求到: %s", ANTHROPIC_TARGET)

    // 转发请求
    forwardRequest(w, proxyReq, client, batchIdx, keyIdx)
}

func handleOpenAIRequest(w http.ResponseWriter, r *http.Request) {
    // 选择可用 Key
    batchIdx, keyIdx, client, factoryKey := selectNextAvailableKey()
    if client == nil {
        jsonError(w, "API key pool exhausted", http.StatusNotImplemented) // 501
        return
    }

    log.Printf("[Proxy] 使用批次 %d, Key 索引 %d", batchIdx, keyIdx)

    // 读取并修改请求体
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

            // OpenAI 特有的处理
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

    // 创建转发请求
    proxyReq, err := http.NewRequest(r.Method, OPENAI_TARGET, bytes.NewReader(bodyBytes))
    if err != nil {
        jsonError(w, "Failed to create proxy request", http.StatusInternalServerError)
        return
    }

    // 复制请求头
    copyHeaders(r, proxyReq)

    // 使用号池 Key
    proxyReq.Header.Del("Authorization")
    proxyReq.Header.Set("Authorization", "Bearer "+factoryKey)
    proxyReq.Header.Set("Host", proxyReq.URL.Host)

    log.Printf("[Proxy] 转发 OpenAI 请求到: %s", OPENAI_TARGET)

    // 转发请求
    forwardRequest(w, proxyReq, client, batchIdx, keyIdx)
}

func handleBedrockRequest(w http.ResponseWriter, r *http.Request) {
    // 选择可用 Key
    batchIdx, keyIdx, client, factoryKey := selectNextAvailableKey()
    if client == nil {
        jsonError(w, "API key pool exhausted", http.StatusNotImplemented) // 501
        return
    }

    log.Printf("[Proxy] 使用批次 %d, Key 索引 %d", batchIdx, keyIdx)

    // 读取并修改请求体
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

    // 创建转发请求
    proxyReq, err := http.NewRequest(r.Method, BEDROCK_TARGET, bytes.NewReader(bodyBytes))
    if err != nil {
        jsonError(w, "Failed to create proxy request", http.StatusInternalServerError)
        return
    }

    // 复制请求头
    copyHeaders(r, proxyReq)

    // 使用号池 Key
    proxyReq.Header.Del("X-Api-Key")
    proxyReq.Header.Del("Authorization")
    proxyReq.Header.Set("Authorization", "Bearer "+factoryKey)
    proxyReq.Header.Set("X-Model-Provider", "bedrock")
    proxyReq.Header.Set("Host", proxyReq.URL.Host)

    log.Printf("[Proxy] 转发 Bedrock 请求到: %s", BEDROCK_TARGET)

    // 转发请求
    forwardRequest(w, proxyReq, client, batchIdx, keyIdx)
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

func forwardRequest(w http.ResponseWriter, proxyReq *http.Request, client *http.Client, batchIdx, keyIdx int) {
    resp, err := client.Do(proxyReq)
    if err != nil {
        log.Printf("[Proxy] 转发请求失败: %v", err)
        jsonError(w, fmt.Sprintf("Bad Gateway: %v", err), http.StatusBadGateway)
        return
    }
    defer resp.Body.Close()

    // 处理 401/402（Key 耗尽）
    if resp.StatusCode == 401 || resp.StatusCode == 402 {
        markKeyAsExhausted(batchIdx, keyIdx)
        log.Printf("[Proxy] Key 耗尽，返回错误给客户端")
    }

    // 复制响应头
    for key, values := range resp.Header {
        for _, value := range values {
            w.Header().Add(key, value)
        }
    }

    // 设置状态码
    w.WriteHeader(resp.StatusCode)

    // 复制响应体
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
