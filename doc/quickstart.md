# 快速开始

## 环境要求
- 安装 Rust 与 Cargo，推荐 `rustup` 管理工具
- Windows PowerShell 终端（本项目示例以 Windows 为主）

## 获取与构建
```powershell
# 克隆并进入目录
# git clone <repository-url>
cd d:\codespace\proxy\ruproxy

# 构建发布版
cargo build --release
```

## 生成示例配置
CLI 已内置示例配置生成功能：
```powershell
cargo run -- generate -o config.json
```
对应实现：`src/main.rs:33-41` 的 `Generate` 子命令。

## 启动代理
使用生成的配置文件启动：
```powershell
cargo run -- run -c config.json
```
- 仅测试配置不启动：
```powershell
cargo run -- run -c config.json --test
```
对应实现：`src/main.rs:22-31` 的 `Run` 子命令与 `run_server` 函数 `src/main.rs:72-161`。

## 校验配置
```powershell
cargo run -- validate -c config.json
```
对应实现：`src/main.rs:38-46` 与 `validate_config` `src/main.rs:253-261`。

## 日志与版本
- 日志初始化：`src/main.rs:51`
- 版本信息：`cargo run -- version`，实现于 `src/main.rs:263-267`

