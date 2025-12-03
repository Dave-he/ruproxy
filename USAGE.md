# 使用文档

## 环境准备
- 安装 Rust 工具链（稳定版）：https://www.rust-lang.org/
- Windows 推荐设置 crates 镜像（网络不佳时）：
  - 在 `~/.cargo/config.toml` 添加：
    ```
    [source.crates-io]
    replace-with = 'rsproxy'
    [source.rsproxy]
    registry = 'https://rsproxy.cn/crates.io-index'
    ```
  - PowerShell 临时环境变量：
    ```powershell
    $env:CARGO_HTTP_MULTIPLEXING = 'false'
    $env:CARGO_NET_RETRY = '10'
    ```

## 快速构建
```powershell
cd ruproxy
cargo build --release
```

## 生成示例配置
```powershell
cargo run -- generate -o config.json
```

## 运行（Xray 风格配置）
```powershell
cargo run -- run -c config.json
```

## 运行（Sing-box 配置）
- 将 sing-box 配置保存为 `singbox.json`
- 当前版本支持读取并转换为内部模型（已接入库），CLI 参数将在后续版本恢复：
  - 若使用 sing-box 配置，建议先通过转换工具或在 `config_singbox.rs` 接口集成到入口

## 入站与端口
- 默认示例包含：
  - SOCKS 入站：`127.0.0.1:1080`
  - HTTP 入站：`127.0.0.1:8080`

## 代理测试
```powershell
# HTTP 代理
curl -x http://127.0.0.1:8080 https://example.com -v

# SOCKS 代理
curl --socks5 127.0.0.1:1080 https://example.com -v
```

## 路由与出站
- 当前已打通 SOCKS 入站的调度管线，默认选择 `direct` 或默认出站；
- 配置中的 `routing.rules` 支持 `outboundTag`（兼容别名）字段；
- 后续版本将增强路由维度（domain/ip/inbound_tag/protocol）与负载均衡策略。

## 常见问题
- 构建拉取依赖超时：配置镜像与 HTTP 参数后重试；
- 运行报错 `FeatureAlreadyExists`：已修复为重复注册忽略；
- Windows 传输模块：为保证稳定，暂未启用 `transport/*` 的平台特性，后续逐步恢复。

