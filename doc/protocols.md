# 协议支持

## Inbound
- `direct`：直连入站，示例处理关闭连接（`src/protocols/direct.rs:49-65`）。
- `shadowsocks`：服务端模式，待完善加解密与转发（`src/protocols/shadowsocks.rs:93-121`）。

## Outbound
- `direct|freedom`：直连目标地址（`src/protocols/direct.rs:73-115`）。
- `shadowsocks`：客户端模式，连接到 SS 服务端并中继（`src/protocols/shadowsocks.rs:134-196`）。

## 传输层
- 结构体定义：`src/config.rs:93-116` 及 `TlsSettings/TcpSettings/WsSettings/HttpSettings/SocketSettings`。
- 具体实现位于 `src/transport/`，当前示例以结构定义与扩展为主。

## 方法支持
- Shadowsocks 加密方法列表：`src/protocols/shadowsocks.rs:213-227`

