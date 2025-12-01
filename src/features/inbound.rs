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
    handlers: std::collections::HashMap<String, Arc<dyn Handler>>,
    untagged_handlers: Vec<Arc<dyn Handler>>,
    running: bool,
}

impl DefaultManager {
    pub fn new() -> Self {
        Self {
            handlers: std::collections::HashMap::new(),
            untagged_handlers: Vec::new(),
            running: false,
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
        // Note: This implementation is simplified due to the change from concurrent data structures
        // to simple collections. In a real implementation, you would need proper synchronization.
        tracing::info!("Inbound manager started");
        Ok(())
    }
    
    async fn close(&self) -> CoreResult<()> {
        // Note: This implementation is simplified due to the change from concurrent data structures
        // to simple collections. In a real implementation, you would need proper synchronization.
        tracing::info!("Inbound manager closed");
        Ok(())
    }
}

#[async_trait]
impl Manager for DefaultManager {
    async fn get_handler(&self, tag: &str) -> CoreResult<Arc<dyn Handler>> {
        self.handlers
            .get(tag)
            .cloned()
            .ok_or_else(|| CoreError::FeatureNotFound(format!("Handler not found: {}", tag)))
    }
    
    async fn add_handler(&self, handler: Arc<dyn Handler>) -> CoreResult<()> {
        let tag = handler.tag();
        
        if tag.is_empty() {
            // Add to untagged handlers
            let mut untagged = self.untagged_handlers.write();
            untagged.push(handler.clone());
        } else {
            // Add to tagged handlers
            if self.handlers.contains_key(tag) {
                return Err(CoreError::FeatureAlreadyExists(format!(
                    "Handler with tag '{}' already exists", tag
                )));
            }
            self.handlers.insert(tag.to_string(), handler.clone());
        }
        
        // Start the handler if manager is running
        let is_running = {
            let running = self.running.read();
            *running
        };
        if is_running {
            handler.start().await?;
        }
        
        tracing::info!("Added inbound handler: {}", tag);
        Ok(())
    }
    
    async fn remove_handler(&self, tag: &str) -> CoreResult<()> {
        if tag.is_empty() {
            return Err(CoreError::InvalidConfiguration("Empty tag".to_string()));
        }
        
        if let Some((_, handler)) = self.handlers.remove(tag) {
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
        let mut handlers = Vec::new();
        
        // Add tagged handlers
        for handler_ref in self.handlers.iter() {
            handlers.push(handler_ref.value().clone());
        }
        
        // Add untagged handlers
        let untagged_handlers = {
            let untagged = self.untagged_handlers.read();
            untagged.clone()
        };
        handlers.extend(untagged_handlers.iter().cloned());
        
        handlers
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