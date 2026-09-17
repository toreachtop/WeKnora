// llm-verify 是一个内网快速验证 WeKnora 外呼 LLM HTTPS 证书处理的独立 demo。
//
// 它复刻了 internal/models/chat/transport.go 中的 TLS 证书处理逻辑：
//   - 默认校验证书（MinVersion=TLS1.2）
//   - 设置环境变量 WEKNORA_LLM_INSECURE_SKIP_VERIFY=true 时跳过校验（等价 Java
//     OkHttpCommonClient 的 ignoreSsl），并打印 warning 日志
//
// 通过一个 gin 测试接口对外暴露，四个参数：请求地址、模型名称、apikey、query。
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	_ "github.com/Tencent/WeKnora/llm-verify/docs"
)

// @title           LLM Verify Demo API
// @version         1.0
// @description     内网快速验证外呼 LLM 的 HTTPS 证书处理（WEKNORA_LLM_INSECURE_SKIP_VERIFY）。
// @BasePath        /api/v1
// @accept          json
// @produce         json
func main() {
	r := gin.Default()

	// 405/404 时返回明确提示，避免“page not found”看不出原因
	r.HandleMethodNotAllowed = true
	r.NoMethod(func(c *gin.Context) {
		c.JSON(http.StatusMethodNotAllowed, gin.H{
			"error": "method not allowed: " + c.Request.Method + " " + c.Request.URL.Path,
			"hint":  "POST /api/v1/chat 才是测试接口；GET 请访问 /swagger/index.html",
		})
	})
	r.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "route not found: " + c.Request.Method + " " + c.Request.URL.Path,
			"available_routes": []string{
				"GET  /healthz",
				"GET  /swagger/index.html",
				"POST /api/v1/chat",
			},
		})
	})

	v1 := r.Group("/api/v1")
	{
		v1.POST("/chat", chatHandler)
	}

	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":               "ok",
			"insecure_skip_verify": strings.EqualFold(strings.TrimSpace(os.Getenv("WEKNORA_LLM_INSECURE_SKIP_VERIFY")), "true"),
		})
	})
	// 浏览器直接访问 / 或 /swagger 时引导到 swagger 页面
	r.GET("/", func(c *gin.Context) { c.Redirect(http.StatusMovedPermanently, "/swagger/index.html") })
	r.GET("/swagger", func(c *gin.Context) { c.Redirect(http.StatusMovedPermanently, "/swagger/index.html") })
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// 端口：默认 8081（本地），容器内由 Dockerfile 的 PORT 环境变量指定
	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "8081"
	}
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("server start failed: %v", err)
	}
}

// ChatRequest 外呼 LLM 测试请求参数
type ChatRequest struct {
	// BaseURL 上游 LLM 兼容接口的根地址，例如 https://openapi.ai.sdd/v1
	BaseURL string `json:"base_url" binding:"required" example:"https://openapi.ai.sdd/v1"`
	// Model 模型名称
	Model string `json:"model" binding:"required" example:"deepseek-chat"`
	// APIKey 鉴权密钥
	APIKey string `json:"api_key" binding:"required" example:"sk-xxx"`
	// Query 发送给模型的内容
	Query string `json:"query" binding:"required" example:"你好"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatCompletionRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
	Stream   bool          `json:"stream"`
}

// chatHandler 调用 OpenAI 兼容的 /chat/completions 接口，验证 HTTPS 证书处理是否生效。
//
// @Summary      外呼 LLM 测试
// @Description  使用请求地址、模型名称、apikey、query 调用 OpenAI 兼容 /chat/completions。
// @Tags         llm
// @Accept       json
// @Produce      json
// @Param        request body ChatRequest true "外呼 LLM 参数"
// @Success      200 {object} map[string]interface{} "上游模型返回（透传）"
// @Failure      400 {object} map[string]interface{} "参数错误"
// @Failure      502 {object} map[string]interface{} "上游调用失败"
// @Router       /chat [post]
func chatHandler(c *gin.Context) {
	var req ChatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 容错：去掉复制粘贴带入的反引号（任意位置）和首尾空白/斜杠
	baseURL := strings.TrimRight(strings.ReplaceAll(strings.TrimSpace(req.BaseURL), "`", ""), "/")
	endpoint := baseURL + "/chat/completions"
	body := chatCompletionRequest{
		Model:    req.Model,
		Messages: []chatMessage{{Role: "user", Content: req.Query}},
		Stream:   false,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	httpReq, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+req.APIKey)

	resp, err := newHTTPClient().Do(httpReq)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	c.Data(resp.StatusCode, "application/json; charset=utf-8", respBody)
}

// newHTTPClient 构造外呼 LLM 使用的 HTTP client，TLS 处理与 WeKnora 主工程保持一致。
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			TLSClientConfig:     newTLSConfig(),
			TLSHandshakeTimeout: 10 * time.Second,
			IdleConnTimeout:     90 * time.Second,
			MaxIdleConnsPerHost: 5,
		},
	}
}

// newTLSConfig 复刻 internal/models/chat/transport.go 的 newChatTLSConfig：
// 默认校验证书，设置 WEKNORA_LLM_INSECURE_SKIP_VERIFY=true 时跳过校验并告警。
func newTLSConfig() *tls.Config {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("WEKNORA_LLM_INSECURE_SKIP_VERIFY")), "true") {
		log.Printf("[WARN] WEKNORA_LLM_INSECURE_SKIP_VERIFY=true: TLS certificate verification is disabled for outbound LLM requests. This must only be used for local development or testing with self-signed or legacy certificates; do not disable SSL verification in production as it exposes connections to man-in-the-middle attacks.")
		return &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true,
		}
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
}
