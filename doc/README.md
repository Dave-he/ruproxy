# ruproxy 文档

本目录提供 ruproxy 的使用说明、配置指南、架构概览与协议支持，帮助你在本地快速构建与运行高性能代理核心。

## 文档导航
- 快速开始：`quickstart.md`
- CLI 使用：`cli.md`
- 配置说明：`config.md`
- 架构概览：`architecture.md`
- 协议支持：`protocols.md`
- 示例配置：`examples/`

## 项目简介
- 以 Rust 编写的高性能代理核心，参考 Xray-core 的分层架构。
- 支持 Inbound/Outbound/Routing 特性与 Direct、Shadowsocks 协议。
- 提供 `TCP/TLS/WebSocket` 传输抽象，易于扩展。

## 快速入口
- 生成示例配置：`cargo run -- generate -o config.json`
- 校验配置：`cargo run -- validate -c config.json`
- 启动运行：`cargo run -- run -c config.json`

