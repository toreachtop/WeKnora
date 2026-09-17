# 多阶段构建：快速打包一个 llm-verify 镜像，用于内网验证外呼 LLM 的 HTTPS 证书处理。
#
# 构建（在 llm-verify 目录内执行）：
#   docker build -t llm-verify:v1 .
# 运行（默认跳过证书校验，适配内网自签名/旧证书场景）：
#   docker run --rm -p 8081:8081 llm-verify:v1
# 运行（严格校验证书）：
#   docker run --rm -p 8081:8081 -e WEKNORA_LLM_INSECURE_SKIP_VERIFY=false llm-verify:v1

# ---------- 构建阶段 ----------
FROM golang:1.26-alpine AS build

WORKDIR /src

# 先拷贝依赖清单，利用层缓存加速后续构建
COPY go.mod go.sum* ./
RUN go mod download

# 拷贝源码并构建
COPY . ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /llm-verify .

# ---------- 运行阶段 ----------
FROM alpine:3.20

# 校验证书需要 CA 根证书
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app
COPY --from=build /llm-verify /app/llm-verify

EXPOSE 8081

# 默认跳过证书校验（内网自签名/旧证书场景）；严格校验请运行时覆盖为 false
ENV WEKNORA_LLM_INSECURE_SKIP_VERIFY=true
# 容器内监听端口，与本地 go run . 的默认值保持一致
ENV PORT=8081

ENTRYPOINT ["/app/llm-verify"]