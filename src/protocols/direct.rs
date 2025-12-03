use crate::common::{HasType, Runnable, CoreResult};
use crate::features::{Feature, inbound, outbound};
use async_trait::async_trait;
use std::any::TypeId;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// Direct connection protocol (no proxy)
pub struct DirectProtocol {
    tag: String,
}

impl DirectProtocol {
    pub fn new(tag: String) -> Self {
        Self { tag }
    }
}

impl HasType for DirectProtocol {
    fn type_id(&self) -> TypeId {
        TypeId::of::<DirectProtocol>()
    }
    
    fn type_name(&self) -> &'static str {
        "DirectProtocol"
    }
}

#[async_trait]
impl Runnable for DirectProtocol {
    async fn start(&self) -> CoreResult<()> {
        tracing::info!("Direct protocol started: {}", self.tag);
        Ok(())
    }
    
    async fn close(&self) -> CoreResult<()> {
        tracing::info!("Direct protocol closed: {}", self.tag);
        Ok(())
    }
}

#[async_trait]
impl inbound::Handler for DirectProtocol {
    fn tag(&self) -> &str {
        &self.tag
    }
    
    async fn handle_connection(
        &self,
        mut stream: TcpStream,
        context: inbound::InboundContext,
    ) -> CoreResult<()> {
        tracing::debug!("Handling direct inbound connection from {}", context.source_addr);
        
        // For direct protocol, we just forward the connection
        // In a real implementation, this would connect to the destination
        // and relay data between the client and destination
        
        // Placeholder implementation - just close the connection
        let _ = stream.shutdown().await;
        
        Ok(())
    }
}

#[async_trait]
impl outbound::Handler for DirectProtocol {
    fn tag(&self) -> &str {
        &self.tag
    }
    
    async fn dispatch(&self, context: outbound::OutboundContext, mut link: outbound::Link) -> CoreResult<()> {
        tracing::debug!("Dispatching direct outbound connection to {}", context.destination_addr);
        
        // Connect directly to the destination
        match TcpStream::connect(context.destination_addr).await {
            Ok(mut dest_stream) => {
                // Relay data between link and destination
                let (mut dest_reader, mut dest_writer) = dest_stream.into_split();
                
                // Spawn tasks to relay data in both directions
                let uplink = tokio::spawn(async move {
                    tokio::io::copy(&mut link.reader, &mut dest_writer).await
                });
                
                let downlink = tokio::spawn(async move {
                    tokio::io::copy(&mut dest_reader, &mut link.writer).await
                });
                
                // Wait for either direction to complete
                tokio::select! {
                    result = uplink => {
                        if let Err(e) = result {
                            tracing::error!("Uplink error: {}", e);
                        }
                    }
                    result = downlink => {
                        if let Err(e) = result {
                            tracing::error!("Downlink error: {}", e);
                        }
                    }
                }
                
                Ok(())
            }
            Err(e) => {
                tracing::error!("Failed to connect to {}: {}", context.destination_addr, e);
                Err(crate::common::CoreError::NetworkError(format!(
                    "Failed to connect to {}: {}", context.destination_addr, e
                )))
            }
        }
    }
}

/// Create a direct inbound handler
pub fn create_direct_inbound(tag: String) -> Arc<dyn inbound::Handler> {
    Arc::new(DirectProtocol::new(tag))
}

/// Create a direct outbound handler
pub fn create_direct_outbound(tag: String) -> Arc<dyn outbound::Handler> {
    Arc::new(DirectProtocol::new(tag))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::inbound::Handler as InboundHandler;
    use crate::features::outbound::Handler as OutboundHandler;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    
    #[tokio::test]
    async fn test_direct_protocol() {
        let protocol = DirectProtocol::new("test".to_string());
        
        assert_eq!(InboundHandler::tag(&protocol), "test");
        assert!(protocol.start().await.is_ok());
        assert!(protocol.close().await.is_ok());
    }
    
    #[test]
    fn test_create_handlers() {
        let inbound = create_direct_inbound("test-in".to_string());
        let outbound = create_direct_outbound("test-out".to_string());
        
        assert_eq!(InboundHandler::tag(inbound.as_ref()), "test-in");
        assert_eq!(OutboundHandler::tag(outbound.as_ref()), "test-out");
    }
}
