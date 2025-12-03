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
        // Default behavior: return protocol error if dispatch is expected but not wired
        Err(crate::common::CoreError::ProtocolError("SOCKS inbound expects dispatch pipeline".to_string()))
    }

    async fn prepare_dispatch(&self, stream: TcpStream, _ctx: &inbound::InboundContext) -> CoreResult<(crate::features::outbound::OutboundContext, crate::features::outbound::Link)> {
        // Perform handshake again to parse destination (duplicated minimal logic); in practice, you would refactor shared parsing
        let mut s = stream;
        let mut buf = [0u8; 2];
        s.read_exact(&mut buf).await?;
        if buf[0] != 0x05 { return Err(crate::common::CoreError::ProtocolError("SOCKS version not supported".to_string())); }
        let nmethods = buf[1] as usize;
        let mut methods = vec![0u8; nmethods];
        s.read_exact(&mut methods).await?;
        let mut chosen = 0x00;
        if let Some(auth) = &self.config.auth { if auth != "noauth" { chosen = 0xFF; } }
        s.write_all(&[0x05, chosen]).await?;
        if chosen == 0xFF { return Err(crate::common::CoreError::ProtocolError("SOCKS auth required".to_string())); }

        let mut head = [0u8; 4];
        s.read_exact(&mut head).await?;
        if head[0] != 0x05 || head[1] != 0x01 { return Err(crate::common::CoreError::ProtocolError("SOCKS only CONNECT supported".to_string())); }
        let atyp = head[3];
        let mut domain_opt: Option<String> = None;
        let destination_addr = match atyp {
            0x01 => {
                let mut addr = [0u8; 4];
                s.read_exact(&mut addr).await?;
                let mut port = [0u8; 2];
                s.read_exact(&mut port).await?;
                let ip = std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
                let p = u16::from_be_bytes(port);
                std::net::SocketAddr::new(std::net::IpAddr::V4(ip), p)
            }
            0x03 => {
                let mut len = [0u8; 1];
                s.read_exact(&mut len).await?;
                let mut domain = vec![0u8; len[0] as usize];
                s.read_exact(&mut domain).await?;
                let mut port = [0u8; 2];
                s.read_exact(&mut port).await?;
                let host = String::from_utf8_lossy(&domain).to_string();
                domain_opt = Some(host.clone());
                let p = u16::from_be_bytes(port);
                let addr = format!("{}:{}", host, p);
                tokio::net::lookup_host(addr).await?.next().ok_or_else(|| crate::common::CoreError::NetworkError("DNS resolve failed".to_string()))?
            }
            0x04 => {
                let mut addr = [0u8; 16];
                s.read_exact(&mut addr).await?;
                let mut port = [0u8; 2];
                s.read_exact(&mut port).await?;
                let ip = std::net::Ipv6Addr::from(addr);
                let p = u16::from_be_bytes(port);
                std::net::SocketAddr::new(std::net::IpAddr::V6(ip), p)
            }
            _ => return Err(crate::common::CoreError::ProtocolError("SOCKS address type unsupported".to_string())),
        };
        s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        let (reader, writer) = s.into_split();
        let link = crate::features::outbound::Link::new(Box::new(reader), Box::new(writer));
        let ctx = if let Some(d) = domain_opt { 
            crate::features::outbound::OutboundContext::new(destination_addr, "tcp".to_string(), self.tag.clone()).with_domain(d)
        } else {
            crate::features::outbound::OutboundContext::new(destination_addr, "tcp".to_string(), self.tag.clone())
        };
        Ok((ctx, link))
    }
    fn receiver_settings(&self) -> Option<serde_json::Value> { serde_json::to_value(&self.config).ok() }
}

pub fn create_socks_inbound(tag: String, config: SocksConfig) -> Arc<dyn inbound::Handler> { Arc::new(SocksInbound::new(tag, config)) }
