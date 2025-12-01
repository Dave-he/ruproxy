# CLI 使用

二进制名：`rust-core`（见 `src/main.rs:11-15`）。支持以下子命令：

## run
启动代理服务。
- 选项：
  - `-c, --config <PATH>` 配置文件路径，默认 `config.json`（`src/main.rs:24-31`）
  - `-t, --test` 仅测试配置并退出
- 行为：加载配置、校验、创建默认实例、注册 inbound/outbound，启动并等待退出信号（`src/main.rs:72-161`）。

## generate
生成示例配置文件。
- 选项：
  - `-o, --output <PATH>` 输出路径，默认 `config.json`（`src/main.rs:33-41`）
- 行为：构造 `Config::default()`，填充示例 inbound/outbound/routing，写入文件（`src/main.rs:163-251`）。

## validate
校验配置文件。
- 选项：
  - `-c, --config <PATH>` 配置文件路径，默认 `config.json`（`src/main.rs:39-46`）
- 行为：读取并调用 `Config::validate()`（`src/main.rs:253-261`，`src/config.rs:452-493`）。

## version
打印版本信息（`src/main.rs:63-69`、`src/main.rs:263-267`）。

