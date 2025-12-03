use crate::common::{HasType, Runnable, CoreResult};
use crate::features::{Feature, inbound};
use async_trait::async_trait;
use std::any::TypeId;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TcpForwardConfig {
    pub address: String,
    pub port: u16,
}

pub struct TcpForwardInbound {
    tag: String,
    config: TcpForwardConfig,
}

impl TcpForwardInbound {
    pub fn new(tag: String, config: TcpForwardConfig) -> Self { Self { tag, config } }
}

impl HasType for TcpForwardInbound {
    fn type_id(&self) -> TypeId { TypeId::of::<TcpForwardInbound>() }
    fn type_name(&self) -> &'static str { "TcpForwardInbound" }
}

#[async_trait]
impl Runnable for TcpForwardInbound {
    async fn start(&self) -> CoreResult<()> { Ok(()) }
    async fn close(&self) -> CoreResult<()> { Ok(()) }
}

#[async_trait]
impl inbound::Handler for TcpForwardInbound {
    fn tag(&self) -> &str { &self.tag }

    async fn handle_connection(&self, mut stream: TcpStream, _context: inbound::InboundContext) -> CoreResult<()> {
        let _ = stream.shutdown().await;
        Ok(())
    }

    async fn prepare_dispatch(&self, stream: TcpStream, _ctx: &inbound::InboundContext) -> CoreResult<(crate::features::outbound::OutboundContext, crate::features::outbound::Link)> {
        let target = format!("{}:{}", self.config.address, self.config.port);
        let addr = tokio::net::lookup_host(target).await?.next().ok_or_else(|| crate::common::CoreError::NetworkError("DNS resolve failed".to_string()))?;
        let (reader, writer) = stream.into_split();
        let link = crate::features::outbound::Link::new(Box::new(reader), Box::new(writer));
        let ctx = crate::features::outbound::OutboundContext::new(addr, "tcp".to_string(), self.tag.clone());
        Ok((ctx, link))
    }

    fn receiver_settings(&self) -> Option<serde_json::Value> { serde_json::to_value(&self.config).ok() }
}

pub fn create_tcp_forward_inbound(tag: String, config: TcpForwardConfig) -> Arc<dyn inbound::Handler> { Arc::new(TcpForwardInbound::new(tag, config)) }
