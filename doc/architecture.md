# 架构概览

## 分层结构
- Protocols：`src/protocols/`，实现 Direct、Shadowsocks 等具体协议。
- Features：`src/features/`，包含 Inbound/Outbound 管理与 Routing。
- Transport：`src/transport/`，抽象 TCP/TLS/WebSocket。
- Core Engine：`src/core.rs`，实例管理与特性装配。
- Config：`src/config.rs`，配置结构、序列化与校验。

## 核心流程
- 启动 CLI `run`：读取配置并校验（`src/main.rs:72-81`）。
- 注册 Inbound/Outbound：按协议装配处理器（`src/main.rs:88-142`）。
- 启动实例与特性：`new_with_defaults()` 创建默认特性集合（`src/core.rs:191-200`）。
- 路由决策：`DefaultRouter.pick_route`（`src/features/routing.rs:248-272`）。

## 设计原则
- 特性接口统一实现 `Feature`（`src/features/mod.rs:10-27`）。
- 管理器提供增删改查与生命周期管理（Inbound/Outbound Manager）。
- 路由规则支持域名与 IP 匹配（`DomainRule`、`IpRule`）。

