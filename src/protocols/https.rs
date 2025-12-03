use crate::common::{HasType, Runnable, CoreResult};
use crate::features::{Feature, inbound};
use async_trait::async_trait;
use std::any::TypeId;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{TlsAcceptor, TlsStream};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HttpsInboundConfig {
    pub tls: crate::config::TlsSettings,
}

pub struct HttpsInbound {
    tag: String,
    config: HttpsInboundConfig,
    server_config: Arc<rustls::ServerConfig>,
}

impl HttpsInbound {
    pub fn new(tag: String, config: HttpsInboundConfig) -> CoreResult<Self> {
        let server_config = build_server_config(&config.tls)?;
        Ok(Self { tag, config, server_config })
    }
}

fn build_server_config(tls: &crate::config::TlsSettings) -> CoreResult<Arc<rustls::ServerConfig>> {
    let mut cert_chain = Vec::new();
    if let Some(certs) = &tls.certificates {
        for c in certs {
            let mut reader = c.certificate.join("\n").into_bytes();
            let certs = rustls_pemfile::certs(&mut reader.as_slice())?;
            for cert in certs { cert_chain.push(rustls::Certificate(cert)); }
        }
    }
    if let Some(cert_file) = &tls.certificate_file {
        let pem = std::fs::read(cert_file)?;
        let mut rdr = pem.as_slice();
        let certs = rustls_pemfile::certs(&mut rdr)?;
        for cert in certs { cert_chain.push(rustls::Certificate(cert)); }
    }
    let mut key_der: Option<Vec<u8>> = None;
    if let Some(keys) = &tls.certificates {
        for c in keys {
            let mut reader = c.key.join("\n").into_bytes();
            let keys = rustls_pemfile::pkcs8_private_keys(&mut reader.as_slice())?;
            if let Some(k) = keys.into_iter().next() { key_der = Some(k); break; }
        }
    }
    if key_der.is_none() {
        if let Some(key_file) = &tls.key_file {
            let pem = std::fs::read(key_file)?;
            let mut rdr = pem.as_slice();
            let keys = rustls_pemfile::pkcs8_private_keys(&mut rdr)?;
            key_der = keys.into_iter().next();
        }
    }
    let key_der = key_der.ok_or_else(|| crate::common::CoreError::InvalidConfiguration("HTTPS inbound requires private key".to_string()))?;
    let mut server_config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, rustls::PrivateKey(key_der))
        .map_err(|e| crate::common::CoreError::InvalidConfiguration(e.to_string()))?;
    Ok(Arc::new(server_config))
}

impl HasType for HttpsInbound {
    fn type_id(&self) -> TypeId { TypeId::of::<HttpsInbound>() }
    fn type_name(&self) -> &'static str { "HttpsInbound" }
}

#[async_trait]
impl Runnable for HttpsInbound {
    async fn start(&self) -> CoreResult<()> { Ok(()) }
    async fn close(&self) -> CoreResult<()> { Ok(()) }
}

#[async_trait]
impl inbound::Handler for HttpsInbound {
    fn tag(&self) -> &str { &self.tag }

    async fn handle_connection(&self, mut stream: TcpStream, _context: inbound::InboundContext) -> CoreResult<()> {
        let acceptor = TlsAcceptor::from(self.server_config.clone());
        let mut tls_stream = acceptor.accept(stream).await?;
        let mut buf = Vec::with_capacity(1024);
        let mut tmp = [0u8; 1024];
        let header;
        loop {
            let n = tls_stream.read(&mut tmp).await?;
            if n == 0 { return Err(crate::common::CoreError::ProtocolError("HTTPS EOF".to_string())); }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(pos) = find_header_end(&buf) { header = buf[..pos].to_vec(); break; }
            if buf.len() > 8192 { return Err(crate::common::CoreError::ProtocolError("HTTPS header too large".to_string())); }
        }
        let text = String::from_utf8_lossy(&header);
        let mut lines = text.lines();
        let request = lines.next().unwrap_or("");
        let parts: Vec<&str> = request.split_whitespace().collect();
        if parts.len() < 3 { return Err(crate::common::CoreError::ProtocolError("Bad HTTPS request".to_string())); }
        let method = parts[0];
        if method.eq_ignore_ascii_case("CONNECT") {
            tls_stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
            // Relay raw ciphertext between client and target is handled by outbound dispatch when using prepare_dispatch
            Ok(())
        } else {
            Err(crate::common::CoreError::ProtocolError("HTTPS dispatch is CONNECT-only".to_string()))
        }
    }

    async fn prepare_dispatch(&self, stream: TcpStream, _ctx: &inbound::InboundContext) -> CoreResult<(crate::features::outbound::OutboundContext, crate::features::outbound::Link)> {
        let acceptor = TlsAcceptor::from(self.server_config.clone());
        let mut tls_stream = acceptor.accept(stream).await?;
        let mut buf = Vec::with_capacity(1024);
        let mut tmp = [0u8; 1024];
        let header;
        loop {
            let n = tls_stream.read(&mut tmp).await?;
            if n == 0 { return Err(crate::common::CoreError::ProtocolError("HTTPS EOF".to_string())); }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(pos) = find_header_end(&buf) { header = buf[..pos].to_vec(); break; }
            if buf.len() > 8192 { return Err(crate::common::CoreError::ProtocolError("HTTPS header too large".to_string())); }
        }
        let text = String::from_utf8_lossy(&header);
        let mut lines = text.lines();
        let request = lines.next().unwrap_or("");
        let parts: Vec<&str> = request.split_whitespace().collect();
        if parts.len() < 3 { return Err(crate::common::CoreError::ProtocolError("Bad HTTPS request".to_string())); }
        let method = parts[0];
        if method.eq_ignore_ascii_case("CONNECT") {
            let target = parts[1];
            let addr = tokio::net::lookup_host(target).await?.next().ok_or_else(|| crate::common::CoreError::NetworkError("DNS resolve failed".to_string()))?;
            tls_stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
            let (reader, writer) = tokio::io::split(tls_stream);
            let link = crate::features::outbound::Link::new(Box::new(reader), Box::new(writer));
            let ctx = crate::features::outbound::OutboundContext::new(addr, "tcp".to_string(), self.tag.clone());
            Ok((ctx, link))
        } else {
            Err(crate::common::CoreError::ProtocolError("HTTPS dispatch is CONNECT-only".to_string()))
        }
    }

    fn receiver_settings(&self) -> Option<serde_json::Value> { serde_json::to_value(&self.config).ok() }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    for i in 3..buf.len() {
        if buf[i-3] == b'\r' && buf[i-2] == b'\n' && buf[i-1] == b'\r' && buf[i] == b'\n' { return Some(i+1-4); }
    }
    None
}

pub fn create_https_inbound(tag: String, config: HttpsInboundConfig) -> Arc<dyn inbound::Handler> { Arc::new(HttpsInbound::new(tag, config).expect("invalid tls config")) }
