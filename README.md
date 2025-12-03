# Rust-Core

A high-performance proxy core written in Rust, inspired by Xray-core architecture.

## Features

- **High Performance**: Built with Rust for maximum performance and memory safety
- **Modular Architecture**: Clean separation of concerns with feature-based design
- **Protocol Support**: Direct connections, Shadowsocks, and extensible protocol framework
- **Transport Layer**: TCP, TLS, WebSocket transport support
- **Flexible Routing**: Domain-based and IP-based routing rules
- **Configuration**: JSON-based configuration compatible with Xray-core concepts
- **Async/Await**: Fully asynchronous implementation using Tokio

## Architecture

The project follows Xray-core's architectural principles but implemented in Rust:

```
┌─────────────────┐
│   Application   │
├─────────────────┤
│   Protocols     │  ← Direct, Shadowsocks, etc.
├─────────────────┤
│   Features      │  ← Inbound, Outbound, Routing
├─────────────────┤
│   Transport     │  ← TCP, TLS, WebSocket
├─────────────────┤
│   Core Engine   │  ← Instance management, DI
└─────────────────┘
```

### Core Components

- **Core**: Instance management and dependency injection
- **Features**: Inbound/Outbound handlers, Routing engine
- **Protocols**: Protocol implementations (Direct, Shadowsocks)
- **Transport**: Network transport layer (TCP, TLS, WebSocket)
- **Config**: Configuration management and validation

## Quick Start

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd rust-core

# Build the project
cargo build --release
```

### Generate Sample Configuration

```bash
cargo run -- generate -o config.json
```

### Run the Proxy

```powershell
# 一键准备
./scripts/setup.ps1

# 启动（使用 config.json）
./scripts/run.ps1 -Config config.json

# 直接运行
cargo run -- run -c config.json
```

### Validate Configuration

```bash
cargo run -- validate -c config.json
```

## Configuration

The configuration format is similar to Xray-core but adapted for Rust-Core:

```json
{
  "log": {
    "level": "info"
  },
  "inbounds": [
    {
      "tag": "http-in",
      "listen": "127.0.0.1",
      "port": 8080,
      "protocol": "direct"
    }
  ],
  "outbounds": [
    {
      "tag": "direct-out",
      "protocol": "direct"
    },
    {
      "tag": "ss-out",
      "protocol": "shadowsocks",
      "settings": {
        "address": "example.com",
        "port": 8388,
        "method": "aes-256-gcm",
        "password": "your-password"
      }
    }
  ],
  "routing": {
    "rules": [
      {
        "tag": "direct-rule",
        "domain": ["localhost", "127.0.0.1"],
        "outbound_tag": "direct-out"
      },
      {
        "tag": "proxy-rule",
        "outbound_tag": "ss-out"
      }
    ]
  }
}
```

## Supported Protocols

### Inbound Protocols
- **Direct**
- **Shadowsocks**
- **SOCKS**
- **HTTP**

### 使用文档
- 详见 `USAGE.md`

### Outbound Protocols
- **Direct/Freedom**: Direct connections to destination
- **Shadowsocks**: Shadowsocks client

### Transport Protocols
- **TCP**: Raw TCP connections
- **TLS**: TLS-encrypted connections
- **WebSocket**: WebSocket transport

## Performance Optimizations

- **Zero-cost abstractions**: Rust's zero-cost abstractions ensure minimal runtime overhead
- **Memory safety**: No garbage collection, predictable memory usage
- **Async I/O**: Fully asynchronous networking with Tokio
- **SIMD support**: Ready for SIMD optimizations in crypto operations
- **Lock-free data structures**: Using DashMap and other lock-free collections

## Development

### Project Structure

```
rust-core/
├── src/
│   ├── common.rs          # Common types and utilities
│   ├── core.rs            # Core instance management
│   ├── config.rs          # Configuration structures
│   ├── features/          # Feature implementations
│   │   ├── inbound.rs     # Inbound handler management
│   │   ├── outbound.rs    # Outbound handler management
│   │   └── routing.rs     # Routing engine
│   ├── protocols/         # Protocol implementations
│   │   ├── direct.rs      # Direct protocol
│   │   └── shadowsocks.rs # Shadowsocks protocol
│   ├── transport/         # Transport layer
│   │   ├── tcp.rs         # TCP transport
│   │   ├── tls.rs         # TLS transport
│   │   └── websocket.rs   # WebSocket transport
│   ├── lib.rs          rary root
│   └── main.rs            # Application entry point
├── Cargo.toml             # Project dependencies
└── README.md              # This file
```

### Running Tests

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_name
```

### Benchmarks

```bash
# Run benchmarks
cargo bench
```

## Comparison with Xray-core

| Feature | Xray-core (Go) | Rust-Core (Rust) |
|---------|----------------|-------------------|
| Memory Safety | GC + Runtime checks | Compile-time guarantees |
| Performance | Good | Excellent |
| Memory Usage | Higher (GC overhead) | Lower (no GC) |
| Concurrency | Goroutines | Async/await |
| Binary Size | Larger | Smaller |
| Development Speed | Faster | Moderate |
| Ecosystem | Mature | Growing |

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run `cargo test` and `cargo clippy`
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Inspired by [Xray-core](https://github.com/XTLS/Xray-core) architecture
- Built with [Tokio](https://tokio.rs/) async runtime
- Uses [rustls](https://github.com/rustls/rustls) for TLS implementation
