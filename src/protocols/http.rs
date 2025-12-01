use crate::common::{HasType, Runnable, CoreResult};
use crate::features::{Feature, inbound};
use async_trait::async_trait;
use std::any::TypeId;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HttpInboundConfig {
    pub address: Option<String>,
    pub port: Option<u16>,
}

pub struct HttpInbound {
    tag: String,
    config: HttpInboundConfig,
}

impl HttpInbound {
    pub fn new(tag: String, config: HttpInboundConfig) -> Self { Self { tag, config } }
}

impl HasType for HttpInbound {
    fn type_id(&self) -> TypeId { TypeId::of::<HttpInbound>() }
    fn type_name(&self) -> &'static str { "HttpInbound" }
}

#[async_trait]
impl Runnable for HttpInbound {
    async fn start(&self) -> CoreResult<()> { Ok(()) }
    async fn close(&self) -> CoreResult<()> { Ok(()) }
}

#[async_trait]
impl inbound::Handler for HttpInbound {
    fn tag(&self) -> &str { &self.tag }
    async fn handle_connection(&self, mut stream: TcpStream, _context: inbound::InboundContext) -> CoreResult<()> {
        let mut buf = Vec::with_capacity(1024);
        let mut tmp = [0u8; 1024];
        let header;
        loop {
            let n = stream.read(&mut tmp).await?;
            if n == 0 { return Err(crate::common::CoreError::ProtocolError("HTTP EOF".to_string())); }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(pos) = find_header_end(&buf) { header = buf[..pos].to_vec(); break; }
            if buf.len() > 8192 { return Err(crate::common::CoreError::ProtocolError("HTTP header too large".to_string())); }
        }
        let text = String::from_utf8_lossy(&header);
        let mut lines = text.lines();
        let request = lines.next().unwrap_or("");
        let parts: Vec<&str> = request.split_whitespace().collect();
        if parts.len() < 3 { return Err(crate::common::CoreError::ProtocolError("Bad HTTP request".to_string())); }
        let method = parts[0];
        if method.eq_ignore_ascii_case("CONNECT") {
            let target = parts[1];
            let addr = tokio::net::lookup_host(target).await?.next().ok_or_else(|| crate::common::CoreError::NetworkError("DNS resolve failed".to_string()))?;
            let mut remote = TcpStream::connect(addr).await?;
            stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
            let (mut r1, mut w1) = stream.into_split();
            let (mut r2, mut w2) = remote.into_split();
            let t1 = tokio::spawn(async move { tokio::io::copy(&mut r1, &mut w2).await });
            let t2 = tokio::spawn(async move { tokio::io::copy(&mut r2, &mut w1).await });
            let _ = tokio::join!(t1, t2);
            Ok(())
        } else {
            // Basic HTTP proxy: extract Host header and connect
            let host_line = header.split(|&b| b == b'\n')
                .filter_map(|l| std::str::from_utf8(l).ok())
                .find(|l| l.to_ascii_lowercase().starts_with("host:"))
                .ok_or_else(|| crate::common::CoreError::ProtocolError("Missing Host".to_string()))?;
            let host = host_line.split(':').skip(1).collect::<Vec<&str>>().join(":").trim().to_string();
            let url = if host.contains(":") { host } else { format!("{}:80", host) };
            let addr = tokio::net::lookup_host(url).await?.next().ok_or_else(|| crate::common::CoreError::NetworkError("DNS resolve failed".to_string()))?;
            let mut remote = TcpStream::connect(addr).await?;
            remote.write_all(&buf).await?;
            let (mut r1, mut w1) = stream.into_split();
            let (mut r2, mut w2) = remote.into_split();
            let t1 = tokio::spawn(async move { tokio::io::copy(&mut r1, &mut w2).await });
            let t2 = tokio::spawn(async move { tokio::io::copy(&mut r2, &mut w1).await });
            let _ = tokio::join!(t1, t2);
            Ok(())
        }
    }
    fn receiver_settings(&self) -> Option<serde_json::Value> { serde_json::to_value(&self.config).ok() }

    async fn prepare_dispatch(&self, mut stream: TcpStream, _context: &inbound::InboundContext) -> CoreResult<(crate::features::outbound::OutboundContext, crate::features::outbound::Link)> {
        let mut buf = Vec::with_capacity(1024);
        let mut tmp = [0u8; 1024];
        let header;
        loop {
            let n = stream.read(&mut tmp).await?;
            if n == 0 { return Err(crate::common::CoreError::ProtocolError("HTTP EOF".to_string())); }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(pos) = find_header_end(&buf) { header = buf[..pos].to_vec(); break; }
            if buf.len() > 8192 { return Err(crate::common::CoreError::ProtocolError("HTTP header too large".to_string())); }
        }
        let text = String::from_utf8_lossy(&header);
        let mut lines = text.lines();
        let request = lines.next().unwrap_or("");
        let parts: Vec<&str> = request.split_whitespace().collect();
        if parts.len() < 3 { return Err(crate::common::CoreError::ProtocolError("Bad HTTP request".to_string())); }
        let method = parts[0];
        if method.eq_ignore_ascii_case("CONNECT") {
            let target = parts[1];
            let addr = tokio::net::lookup_host(target).await?.next().ok_or_else(|| crate::common::CoreError::NetworkError("DNS resolve failed".to_string()))?;
            stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
            let (reader, writer) = stream.into_split();
            let link = crate::features::outbound::Link::new(Box::new(reader), Box::new(writer));
            let ctx = crate::features::outbound::OutboundContext::new(addr, "tcp".to_string(), self.tag.clone());
            Ok((ctx, link))
        } else {
            Err(crate::common::CoreError::ProtocolError("HTTP dispatch is CONNECT-only".to_string()))
        }
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    for i in 3..buf.len() {
        if buf[i-3] == b'\r' && buf[i-2] == b'\n' && buf[i-1] == b'\r' && buf[i] == b'\n' { return Some(i+1-4); }
    }
    None
}

pub fn create_http_inbound(tag: String, config: HttpInboundConfig) -> Arc<dyn inbound::Handler> { Arc::new(HttpInbound::new(tag, config)) }
    
