pub mod direct;
pub mod shadowsocks;
pub mod socks;
pub mod http;
pub mod tcp_forward;

// Re-export commonly used types
pub use direct::DirectProtocol;
pub use shadowsocks::ShadowsocksProtocol;
pub use socks::{SocksConfig, create_socks_inbound};
pub use http::{HttpInboundConfig, create_http_inbound};
pub use tcp_forward::{TcpForwardConfig, create_tcp_forward_inbound};
