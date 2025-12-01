use crate::common::{HasType, Runnable, CoreResult};
use crate::features::{Feature, inbound};
use async_trait::async_trait;
use std::any::TypeId;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SocksConfig {
    pub auth: Option<String>,
    pub udp: Option<bool>,
    pub address: Option<String>,
    pub port: Option<u16>,
}

pub struct SocksInbound {
    tag: String,
    config: SocksConfig,
}

impl SocksInbound {
    pub fn new(tag: String, config: SocksConfig) -> Self { Self { tag, config } }
}

impl HasType for SocksInbound {
    fn type_id(&self) -> TypeId { TypeId::of::<SocksInbound>() }
    fn type_name(&self) -> &'static str { "SocksInbound" }
}

#[async_trait]
impl Runnable for SocksInbound {
    async fn start(&self) -> CoreResult<()> { Ok(()) }
    async fn close(&self) -> CoreResult<()> { Ok(()) }
}

#[async_trait]
impl inbound::Handler for SocksInbound {
    fn tag(&self) -> &str { &self.tag }
    async fn handle_connection(&self, mut stream: TcpStream, _context: inbound::InboundContext) -> CoreResult<()> {
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;
        if buf[0] != 0x05 { return Err(crate::common::CoreError::ProtocolError("SOCKS version not supported".to_string())); }
        let nmethods = buf[1] as usize;
        let mut methods = vec![0u8; nmethods];
        stream.read_exact(&mut methods).await?;
        let mut chosen = 0x00;
        if let Some(auth) = &self.config.auth { if auth != "noauth" { chosen = 0xFF; } }
        stream.write_all(&[0x05, chosen]).await?;
        if chosen == 0xFF { return Err(crate::common::CoreError::ProtocolError("SOCKS auth required".to_string())); }

        let mut head = [0u8; 4];
        stream.read_exact(&mut head).await?;
        if head[0] != 0x05 || head[1] != 0x01 { return Err(crate::common::CoreError::ProtocolError("SOCKS only CONNECT supported".to_string())); }
        let atyp = head[3];
        let dest = match atyp {
            0x01 => {
                let mut addr = [0u8; 4];
                stream.read_exact(&mut addr).await?;
                let mut port = [0u8; 2];
                stream.read_exact(&mut port).await?;
                let ip = std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
                let p = u16::from_be_bytes(port);
                std::net::SocketAddr::new(std::net::IpAddr::V4(ip), p)
            }
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut domain = vec![0u8; len[0] as usize];
                stream.read_exact(&mut domain).await?;
                let mut port = [0u8; 2];
                stream.read_exact(&mut port).await?;
                let host = String::from_utf8_lossy(&domain).to_string();
                let p = u16::from_be_bytes(port);
                let addr = format!("{}:{}", host, p);
                tokio::net::lookup_host(addr).await?.next().ok_or_else(|| crate::common::CoreError::NetworkError("DNS resolve failed".to_string()))?
            }
            0x04 => {
                let mut addr = [0u8; 16];
                stream.read_exact(&mut addr).await?;
                let mut port = [0u8; 2];
                stream.read_exact(&mut port).await?;
                let ip = std::net::Ipv6Addr::from(addr);
                let p = u16::from_be_bytes(port);
                std::net::SocketAddr::new(std::net::IpAddr::V6(ip), p)
            }
            _ => return Err(crate::common::CoreError::ProtocolError("SOCKS address type unsupported".to_string())),
        };

        stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;

        match TcpStream::connect(dest).await {
            Ok(mut remote) => {
                let (mut r1, mut w1) = stream.into_split();
                let (mut r2, mut w2) = remote.into_split();
                let t1 = tokio::spawn(async move { tokio::io::copy(&mut r1, &mut w2).await });
                let t2 = tokio::spawn(async move { tokio::io::copy(&mut r2, &mut w1).await });
                let _ = tokio::join!(t1, t2);
                Ok(())
            }
            Err(e) => Err(crate::common::CoreError::NetworkError(format!("connect failed: {}", e))),
        }
    }
    fn receiver_settings(&self) -> Option<serde_json::Value> { serde_json::to_value(&self.config).ok() }
}

pub fn create_socks_inbound(tag: String, config: SocksConfig) -> Arc<dyn inbound::Handler> { Arc::new(SocksInbound::new(tag, config)) }
