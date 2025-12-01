pub mod direct;
pub mod shadowsocks;

// Re-export commonly used types
pub use direct::DirectProtocol;
pub use shadowsocks::ShadowsocksProtocol;