use crate::common::{HasType, Runnable, CoreResult, CoreError};
use crate::features::Feature;
use async_trait::async_trait;
use std::any::TypeId;
use std::sync::Arc;
use tokio::net::TcpStream;

/// Context for inbound connections
#[derive(Debug, Clone)]
pub struct InboundContext {
    pub source_addr: std::net::SocketAddr,
    pub destination_addr: std::net::SocketAddr,
    pub protocol: String,
    pub user_id: Option<String>,
    pub inbound_tag: String,
}

impl InboundContext {
    pub fn new(
        source_addr: std::net::SocketAddr,
        destination_addr: std::net::SocketAddr,
        protocol: String,
        inbound_tag: String,
    ) -> Self {
        Self {
            source_addr,
            destination_addr,
            protocol,
            user_id: None,
            inbound_tag,
        }
    }
}

/// Handler for processing inbound connections
#[async_trait]
pub trait Handler: Feature {
    /// Get the tag of this handler
    fn tag(&self) -> &str;
    
    /// Handle an incoming connection
    async fn handle_connection(
        &self,
        stream: TcpStream,
        context: InboundContext,
    ) -> CoreResult<()>;

    /// Optional: prepare outbound dispatch by extracting target and wrapping the client stream
    /// Default: not supported
    async fn prepare_dispatch(
        &self,
        _stream: TcpStream,
        _context: &InboundContext,
    ) -> CoreResult<(crate::features::outbound::OutboundContext, crate::features::outbound::Link)> {
        Err(CoreError::ProtocolError("prepare_dispatch not supported".to_string()))
    }
    
    /// Get receiver settings (for configuration)
    fn receiver_settings(&self) -> Option<serde_json::Value> {
        None
    }
    
    /// Get proxy settings (for configuration)
    fn proxy_settings(&self) -> Option<serde_json::Value> {
        None
    }
}

/// Manager for inbound handlers
#[async_trait]
pub trait Manager: Feature {
    /// Get a handler by tag
    async fn get_handler(&self, tag: &str) -> CoreResult<Arc<dyn Handler>>;
    
    /// Add a handler to the manager
    async fn add_handler(&self, handler: Arc<dyn Handler>) -> CoreResult<()>;
    
    /// Remove a handler by tag
    async fn remove_handler(&self, tag: &str) -> CoreResult<()>;
    
    /// List all handlers
    async fn list_handlers(&self) -> Vec<Arc<dyn Handler>>;
}

/// Type identifier for Manager trait
pub fn manager_type() -> TypeId {
    TypeId::of::<dyn Manager>()
}

/// Default implementation of inbound manager
pub struct DefaultManager {
    handlers: parking_lot::RwLock<std::collections::HashMap<String, Arc<dyn Handler>>>,
    untagged_handlers: parking_lot::RwLock<Vec<Arc<dyn Handler>>>,
    running: parking_lot::RwLock<bool>,
}

impl DefaultManager {
    pub fn new() -> Self {
        Self {
            handlers: parking_lot::RwLock::new(std::collections::HashMap::new()),
            untagged_handlers: parking_lot::RwLock::new(Vec::new()),
            running: parking_lot::RwLock::new(false),
        }
    }
}

impl Default for DefaultManager {
    fn default() -> Self {
        Self::new()
    }
}

impl HasType for DefaultManager {
    fn type_id(&self) -> TypeId {
        manager_type()
    }
    
    fn type_name(&self) -> &'static str {
        "InboundManager"
    }
}

#[async_trait]
impl Runnable for DefaultManager {
    async fn start(&self) -> CoreResult<()> {
        *self.running.write() = true;
        let handlers: Vec<Arc<dyn Handler>> = self.handlers.read().values().cloned().collect();
        let untagged: Vec<Arc<dyn Handler>> = self.untagged_handlers.read().iter().cloned().collect();
        for handler in handlers { let _ = handler.start().await; }
        for handler in untagged { let _ = handler.start().await; }
        tracing::info!("Inbound manager started");
        Ok(())
    }
    
    async fn close(&self) -> CoreResult<()> {
        *self.running.write() = false;
        let handlers: Vec<Arc<dyn Handler>> = self.handlers.read().values().cloned().collect();
        let untagged: Vec<Arc<dyn Handler>> = self.untagged_handlers.read().iter().cloned().collect();
        for handler in handlers { let _ = handler.close().await; }
        for handler in untagged { let _ = handler.close().await; }
        tracing::info!("Inbound manager closed");
        Ok(())
    }
}

#[async_trait]
impl Manager for DefaultManager {
    async fn get_handler(&self, tag: &str) -> CoreResult<Arc<dyn Handler>> {
        self.handlers
            .read()
            .get(tag)
            .cloned()
            .ok_or_else(|| CoreError::FeatureNotFound(format!("Handler not found: {}", tag)))
    }
    
    async fn add_handler(&self, handler: Arc<dyn Handler>) -> CoreResult<()> {
        let tag = handler.tag();
        
        if tag.is_empty() {
            let mut untagged = self.untagged_handlers.write();
            untagged.push(handler.clone());
        } else {
            let mut handlers = self.handlers.write();
            if handlers.contains_key(tag) {
                return Err(CoreError::FeatureAlreadyExists(format!(
                    "Handler with tag '{}' already exists", tag
                )));
            }
            handlers.insert(tag.to_string(), handler.clone());
        }
        if *self.running.read() {
            handler.start().await?;
        }
        
        tracing::info!("Added inbound handler: {}", tag);
        Ok(())
    }
    
    async fn remove_handler(&self, tag: &str) -> CoreResult<()> {
        if tag.is_empty() {
            return Err(CoreError::InvalidConfiguration("Empty tag".to_string()));
        }
        
        let handler = { let mut h = self.handlers.write(); h.remove(tag) };
        if let Some(handler) = handler {
            if let Err(e) = handler.close().await {
                tracing::warn!("Failed to close handler {}: {}", tag, e);
            }
            tracing::info!("Removed inbound handler: {}", tag);
            Ok(())
        } else {
            Err(CoreError::FeatureNotFound(format!("Handler not found: {}", tag)))
        }
    }
    
    async fn list_handlers(&self) -> Vec<Arc<dyn Handler>> {
        let mut list = Vec::new();
        for h in self.handlers.read().values() { list.push(h.clone()); }
        let untag = self.untagged_handlers.read().clone();
        list.extend(untag.into_iter());
        list
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    
    struct TestHandler {
        tag: String,
        started: AtomicBool,
    }
    
    impl TestHandler {
        fn new(tag: &str) -> Self {
            Self {
                tag: tag.to_string(),
                started: AtomicBool::new(false),
            }
        }
    }
    
    impl HasType for TestHandler {
        fn type_id(&self) -> TypeId {
            TypeId::of::<TestHandler>()
        }
        
        fn type_name(&self) -> &'static str {
            "TestHandler"
        }
    }
    
    #[async_trait]
    impl Runnable for TestHandler {
        async fn start(&self) -> CoreResult<()> {
            self.started.store(true, Ordering::Relaxed);
            Ok(())
        }
        
        async fn close(&self) -> CoreResult<()> {
            self.started.store(false, Ordering::Relaxed);
            Ok(())
        }
    }
    
    #[async_trait]
    impl Handler for TestHandler {
        fn tag(&self) -> &str {
            &self.tag
        }
        
        async fn handle_connection(
            &self,
            _stream: TcpStream,
            _context: InboundContext,
        ) -> CoreResult<()> {
            Ok(())
        }
    }
    
    #[tokio::test]
    async fn test_inbound_manager() {
        let manager = DefaultManager::new();
        let handler = Arc::new(TestHandler::new("test"));
        
        // Test adding handler
        assert!(manager.add_handler(handler.clone()).await.is_ok());
        
        // Test getting handler
        let retrieved = manager.get_handler("test").await.unwrap();
        assert_eq!(retrieved.tag(), "test");
        
        // Test starting manager
        assert!(manager.start().await.is_ok());
        assert!(handler.started.load(Ordering::Relaxed));
        
        // Test removing handler
        assert!(manager.remove_handler("test").await.is_ok());
        assert!(!handler.started.load(Ordering::Relaxed));
        
        // Test closing manager
        assert!(manager.close().await.is_ok());
    }
}
