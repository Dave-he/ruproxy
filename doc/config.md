# 配置说明

配置为 JSON 格式，结构定义见 `src/config.rs`。核心段落：
- `log` 日志配置（`src/config.rs:33-47`）
- `inbounds` 入站列表（`src/config.rs:49-72`）
- `outbounds` 出站列表（`src/config.rs:74-91`）
- `routing` 路由配置（`src/config.rs:231-242`、`src/config.rs:244-289`）
- `dns`、`policy`、`stats`、`apps` 等可选段（`src/config.rs:315-423`）
- 传输层 `stream_settings` 包含 `tls/tcp/ws/http/socket` 等（`src/config.rs:93-116` 及各子结构体）

## 最小示例
```json
{
  "log": { "level": "info" },
  "inbounds": [
    { "tag": "http-in", "listen": "127.0.0.1", "port": 8080, "protocol": "direct" }
  ],
  "outbounds": [
    { "tag": "direct-out", "protocol": "direct" }
  ],
  "routing": { "rules": [ { "outbound_tag": "direct-out" } ] }
}
```

## Shadowsocks 示例
```json
{
  "log": { "level": "info" },
  "inbounds": [
    { "tag": "ss-in", "listen": "0.0.0.0", "port": 8388, "protocol": "shadowsocks",
      "settings": { "address": null, "port": 8388, "method": "aes-256-gcm", "password": "your-password", "udp": true }
    }
  ],
  "outbounds": [
    { "tag": "direct-out", "protocol": "direct" },
    { "tag": "ss-out", "protocol": "shadowsocks",
      "settings": { "address": "example.com", "port": 8388, "method": "aes-256-gcm", "password": "your-password", "udp": true }
    }
  ],
  "routing": {
    "rules": [
      { "tag": "local", "domain": ["localhost", "127.0.0.1"], "outbound_tag": "direct-out" },
      { "tag": "proxy", "outbound_tag": "ss-out" }
    ]
  }
}
```

## 字段要点
- `inbounds[].protocol`：支持 `direct`、`shadowsocks`（`src/main.rs:94-113`）
- `outbounds[].protocol`：支持 `direct|freedom`、`shadowsocks`（`src/main.rs:122-141`）
- `routing.rules[].type` 映射为 `field`（`src/config.rs:250-253`）
- 验证规则：至少一个 inbound/outbound，标签唯一（`src/config.rs:452-493`）

## Sing-box 配置导入
支持从 sing-box JSON 转换：`src/config_singbox.rs:4-44`，可根据需要调用 `from_singbox_json` 将其转为本项目配置结构。

