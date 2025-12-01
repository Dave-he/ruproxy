use crate::common::{HasType, Runnable, CoreResult};
use crate::features::{Feature, inbound, outbound};
use async_trait::async_trait;
use std::any::TypeId;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use serde::{Deserialize, Serialize};

/// Shadowsocks configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowsocksConfig {
    /// Server address (for outbound) or listen address (for inbound)
    pub address: Option<String>,
    
    /// Port
    pub port: u16,
    
    /// Encryption method
    pub method: String,
    
    /// Password
    pub password: String,
    
    /// UDP support
    pub udp: Option<bool>,
    
    /// Level (for policy)
    pub level: Option<u32>,
    
    /// Email (for user identification)
    pub email: Option<String>,
}

/// Shadowsocks protocol implementation
pub struct ShadowsocksProtocol {
    tag: String,
    config: ShadowsocksConfig,
    is_server: bool,
}

impl ShadowsocksProtocol {
    pub fn new_server(tag: String, config: ShadowsocksConfig) -> Self {
        Self {
            tag,
            config,
            is_server: true,
        }
    }
    
    pub fn new_client(tag: String, config: ShadowsocksConfig) -> Self {
        Self {
            tag,
            config,
            is_server: false,
        }
    }
}

impl HasType for ShadowsocksProtocol {
    fn type_id(&self) -> TypeId {
        TypeId::of::<ShadowsocksProtocol>()
    }
    
    fn type_name(&self) -> &'static str {
        "ShadowsocksProtocol"
    }
}

#[async_trait]
impl Runnable for ShadowsocksProtocol {
    async fn start(&self) -> CoreResult<()> {
        tracing::info!(
            "Shadowsocks protocol started: {} ({})", 
            self.tag,
            if self.is_server { "server" } else { "client" }
        );
        Ok(())
    }
    
    async fn close(&self) -> CoreResult<()> {
        tracing::info!("Shadowsocks protocol closed: {}", self.tag);
        Ok(())
    }
}

#[async_trait]
impl inbound::Handler for ShadowsocksProtocol {
    fn tag(&self) -> &str {
        &self.tag
    }
    
    async fn handle_connection(
        &self,
        mut stream: TcpStream,
        context: inbound::InboundContext,
    ) -> CoreResult<()> {
        if !self.is_server {
            return Err(crate::common::CoreError::ProtocolError(
                "Cannot use client config for inbound".to_string()
            ));
        }
        
        tracing::debug!(
            "Handling Shadowsocks inbound connection from {} with method {}", 
            context.source_addr,
            self.config.method
        );
        
        // TODO: Implement actual Shadowsocks server protocol
        // This would involve:
        // 1. Reading and decrypting the initial request
        // 2. Parsing the target address
        // 3. Establishing connection to target
        // 4. Relaying encrypted data
        
        // Placeholder implementation
        let _ = stream.shutdown().await;
        
        Ok(())
    }
    
    fn proxy_settings(&self) -> Option<serde_json::Value> {
        serde_json::to_value(&self.config).ok()
    }
}

#[async_trait]
impl outbound::Handler for ShadowsocksProtocol {
    fn tag(&self) -> &str {
        &self.tag
    }
    
    async fn dispatch(&self, context: outbound::OutboundContext, mut link: outbound::Link) -> CoreResult<()> {
        if self.is_server {
            return Err(crate::common::CoreError::ProtocolError(
                "Cannot use server config for outbound".to_string()
            ));
        }
        
        tracing::debug!(
            "Dispatching Shadowsocks outbound connection to {} via {}:{} with method {}", 
            context.destination_addr,
            self.config.address.as_deref().unwrap_or("unknown"),
            self.config.port,
            self.config.method
        );
        
        // Connect to Shadowsocks server
        let server_addr = format!(
            "{}:{}", 
            self.config.address.as_deref().unwrap_or("127.0.0.1"),
            self.config.port
        );
        
        match TcpStream::connect(&server_addr).await {
            Ok(mut server_stream) => {
                // TODO: Implement actual Shadowsocks client protocol
                // This would involve:
                // 1. Sending encrypted request with target address
                // 2. Relaying encrypted data between client and server
                
                // Placeholder implementation - just relay raw data
                let (mut server_reader, mut server_writer) = server_stream.into_split();
                
                let uplink = tokio::spawn(async move {
                    tokio::io::copy(&mut link.reader, &mut server_writer).await
                });
                
                let downlink = tokio::spawn(async move {
                    tokio::io::copy(&mut server_reader, &mut link.writer).await
                });
                
                tokio::select! {
                    result = uplink => {
                        if let Err(e) = result {
                            tracing::error!("Shadowsocks uplink error: {}", e);
                        }
                    }
                    result = downlink => {
                        if let Err(e) = result {
                            tracing::error!("Shadowsocks downlink error: {}", e);
                        }
                    }
                }
                
                Ok(())
            }
            Err(e) => {
                tracing::error!("Failed to connect to Shadowsocks server {}: {}", server_addr, e);
                Err(crate::common::CoreError::NetworkError(format!(
                    "Failed to connect to Shadowsocks server {}: {}", server_addr, e
                )))
            }
        }
    }
    
    fn proxy_settings(&self) -> Option<serde_json::Value> {
        serde_json::to_value(&self.config).ok()
    }
}

/// Create a Shadowsocks inbound handler (server)
pub fn create_shadowsocks_inbound(tag: String, config: ShadowsocksConfig) -> Arc<dyn inbound::Handler> {
    Arc::new(ShadowsocksProtocol::new_server(tag, config))
}

/// Create a Shadowsocks outbound handler (client)
pub fn create_shadowsocks_outbound(tag: String, config: ShadowsocksConfig) -> Arc<dyn outbound::Handler> {
    Arc::new(ShadowsocksProtocol::new_client(tag, config))
}

/// Supported Shadowsocks encryption methods
pub const SUPPORTED_METHODS: &[&str] = &[
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
];

/// Check if a method is supported
pub fn is_method_supported(method: &str) -> bool {
    SUPPORTED_METHODS.contains(&method)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_shadowsocks_protocol() {
        let config = ShadowsocksConfig {
            address: Some("127.0.0.1".to_string()),
            port: 8388,
            method: "aes-256-gcm".to_string(),
            password: "test-password".to_string(),
            udp: Some(true),
            level: Some(0),
            email: None,
        };
        
        let server = ShadowsocksProtocol::new_server("test-server".to_string(), config.clone());
        let client = ShadowsocksProtocol::new_client("test-client".to_string(), config);
        
        assert_eq!(server.tag(), "test-server");
        assert_eq!(client.tag(), "test-client");
        assert!(server.is_server);
        assert!(!client.is_server);
        
        assert!(server.start().await.is_ok());
        assert!(client.start().await.is_ok());
        assert!(server.close().await.is_ok());
        assert!(client.close().await.is_ok());
    }
    
    #[test]
    fn test_supported_methods() {
        assert!(is_method_supported("aes-256-gcm"));
        assert!(is_method_supported("chacha20-ietf-poly1305"));
        assert!(!is_method_supported("unsupported-method"));
    }
    
    #[test]
    fn test_create_handlers() {
        let config = ShadowsocksConfig {
            address: Some("127.0.0.1".to_string()),
            port: 8388,
            method: "aes-256-gcm".to_string(),
            password: "test-password".to_string(),
            udp: Some(true),
            level: Some(0),
            email: None,
        };
        
        let inbound = create_shadowsocks_inbound("test-in".to_string(), config.clone());
        let outbound = create_shadowsocks_outbound("test-out".to_string(), config);
        
        assert_eq!(inbound.tag(), "test-in");
        assert_eq!(outbound.tag(), "test-out");
    }
}