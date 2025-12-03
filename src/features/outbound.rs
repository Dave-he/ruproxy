use crate::common::{HasType, Runnable, CoreResult, CoreError};
use crate::features::Feature;
use async_trait::async_trait;
use std::any::TypeId;
use std::sync::Arc;


/// Context for outbound connections
#[derive(Debug, Clone)]
pub struct OutboundContext {
    pub destination_addr: std::net::SocketAddr,
    pub protocol: String,
    pub user_id: Option<String>,
    pub outbound_tag: String,
    pub source_addr: Option<std::net::SocketAddr>,
    pub domain: Option<String>,
}

impl OutboundContext {
    pub fn new(
        destination_addr: std::net::SocketAddr,
        protocol: String,
        outbound_tag: String,
    ) -> Self {
        Self {
            destination_addr,
            protocol,
            user_id: None,
            outbound_tag,
            source_addr: None,
            domain: None,
        }
    }
}

impl OutboundContext {
    pub fn with_domain(mut self, domain: String) -> Self {
        self.domain = Some(domain);
        self
    }
}

/// Transport link for data transmission
pub struct Link {
    pub reader: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
    pub writer: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
}

impl Link {
    pub fn new(
        reader: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        writer: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    ) -> Self {
        Self { reader, writer }
    }
}

/// Handler for processing outbound connections
#[async_trait]
pub trait Handler: Feature {
    /// Get the tag of this handler
    fn tag(&self) -> &str;
    
    /// Dispatch data through this outbound handler
    async fn dispatch(&self, context: OutboundContext, link: Link) -> CoreResult<()>;
    
    /// Get sender settings (for configuration)
    fn sender_settings(&self) -> Option<serde_json::Value> {
        None
    }
    
    /// Get proxy settings (for configuration)
    fn proxy_settings(&self) -> Option<serde_json::Value> {
        None
    }
}

/// Selector for choosing outbound handlers
pub trait HandlerSelector: Send + Sync {
    /// Select handlers from the given list
    fn select(&self, tags: &[String]) -> Vec<String>;
}

/// Manager for outbound handlers
#[async_trait]
pub trait Manager: Feature {
    /// Get a handler by tag
    fn get_handler(&self, tag: &str) -> Option<Arc<dyn Handler>>;
    
    /// Get the default handler
    fn get_default_handler(&self) -> Option<Arc<dyn Handler>>;
    
    /// Add a handler to the manager
    async fn add_handler(&self, handler: Arc<dyn Handler>) -> CoreResult<()>;
    
    /// Remove a handler by tag
    async fn remove_handler(&self, tag: &str) -> CoreResult<()>;
    
    /// List all handlers
    fn list_handlers(&self) -> Vec<Arc<dyn Handler>>;
}

/// Type identifier for Manager trait
pub fn manager_type() -> TypeId {
    TypeId::of::<dyn Manager>()
}

/// Default implementation of outbound manager
pub struct DefaultManager {
    handlers: parking_lot::RwLock<std::collections::HashMap<String, Arc<dyn Handler>>>,
    default_handler: parking_lot::RwLock<Option<Arc<dyn Handler>>>,
    running: parking_lot::RwLock<bool>,
}

impl DefaultManager {
    pub fn new() -> Self {
        Self {
            handlers: parking_lot::RwLock::new(std::collections::HashMap::new()),
            default_handler: parking_lot::RwLock::new(None),
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
        "OutboundManager"
    }
}

#[async_trait]
impl Runnable for DefaultManager {
    async fn start(&self) -> CoreResult<()> {
        *self.running.write() = true;
        let handlers: Vec<Arc<dyn Handler>> = self.handlers.read().values().cloned().collect();
        let default = self.default_handler.read().clone();
        for handler in handlers { let _ = handler.start().await; }
        if let Some(h) = default { let _ = h.start().await; }
        tracing::info!("Outbound manager started");
        Ok(())
    }
    
    async fn close(&self) -> CoreResult<()> {
        *self.running.write() = false;
        let handlers: Vec<Arc<dyn Handler>> = self.handlers.read().values().cloned().collect();
        let default = self.default_handler.read().clone();
        for handler in handlers { let _ = handler.close().await; }
        if let Some(h) = default { let _ = h.close().await; }
        tracing::info!("Outbound manager closed");
        Ok(())
    }
}

#[async_trait]
impl Manager for DefaultManager {
    fn get_handler(&self, tag: &str) -> Option<Arc<dyn Handler>> {
        self.handlers.read().get(tag).cloned()
    }
    
    fn get_default_handler(&self) -> Option<Arc<dyn Handler>> {
        self.default_handler.read().clone()
    }
    
    async fn add_handler(&self, handler: Arc<dyn Handler>) -> CoreResult<()> {
        let tag = handler.tag().to_string();
        
        if self.handlers.read().contains_key(&tag) {
            return Err(CoreError::FeatureAlreadyExists(format!(
                "Outbound handler with tag '{}' already exists", tag
            )));
        }
        {
            let mut default = self.default_handler.write();
            if default.is_none() { *default = Some(handler.clone()); }
            self.handlers.write().insert(tag.clone(), handler.clone());
        }
        let is_running = *self.running.read();
        if is_running { handler.start().await?; }
        
        tracing::info!("Added outbound handler: {}", tag);
        Ok(())
    }
    
    async fn remove_handler(&self, tag: &str) -> CoreResult<()> {
        let handler = {
            let mut map = self.handlers.write();
            let h = map.remove(tag);
            let mut default = self.default_handler.write();
            if default.as_ref().map(|dh| dh.tag() == tag).unwrap_or(false) {
                *default = map.values().next().cloned();
            }
            h
        };
        if let Some(handler) = handler {
            
            if let Err(e) = handler.close().await {
                tracing::warn!("Failed to close outbound handler {}: {}", tag, e);
            }
            
            tracing::info!("Removed outbound handler: {}", tag);
            Ok(())
        } else {
            Err(CoreError::FeatureNotFound(format!("Handler not found: {}", tag)))
        }
    }
    
    fn list_handlers(&self) -> Vec<Arc<dyn Handler>> {
        self.handlers.read().values().cloned().collect()
    }
}

/// Simple round-robin handler selector
pub struct RoundRobinSelector {
    counter: parking_lot::Mutex<usize>,
}

impl RoundRobinSelector {
    pub fn new() -> Self {
        Self {
            counter: parking_lot::Mutex::new(0),
        }
    }
}

impl Default for RoundRobinSelector {
    fn default() -> Self {
        Self::new()
    }
}

impl HandlerSelector for RoundRobinSelector {
    fn select(&self, tags: &[String]) -> Vec<String> {
        if tags.is_empty() {
            return Vec::new();
        }
        
        let mut counter = self.counter.lock();
        let index = *counter % tags.len();
        *counter = (*counter + 1) % tags.len();
        
        vec![tags[index].clone()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{AsyncRead, AsyncWrite};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    
    struct MockStream;
    
    impl AsyncRead for MockStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    
    impl AsyncWrite for MockStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            Poll::Ready(Ok(0))
        }
        
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }
        
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }
    }
    
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
        
        async fn dispatch(&self, _context: OutboundContext, _link: Link) -> CoreResult<()> {
            Ok(())
        }
    }
    
    #[tokio::test]
    async fn test_outbound_manager() {
        let manager = DefaultManager::new();
        let handler = Arc::new(TestHandler::new("test"));
        
        // Test adding handler
        assert!(manager.add_handler(handler.clone()).await.is_ok());
        
        // Test getting handler
        let retrieved = manager.get_handler("test").unwrap();
        assert_eq!(retrieved.tag(), "test");
        
        // Test default handler
        let default = manager.get_default_handler().unwrap();
        assert_eq!(default.tag(), "test");
        
        // Test starting manager
        assert!(manager.start().await.is_ok());
        assert!(handler.started.load(Ordering::Relaxed));
        
        // Test removing handler
        assert!(manager.remove_handler("test").await.is_ok());
        assert!(!handler.started.load(Ordering::Relaxed));
        
        // Test closing manager
        assert!(manager.close().await.is_ok());
    }
    
    #[test]
    fn test_round_robin_selector() {
        let selector = RoundRobinSelector::new();
        let tags = vec!["tag1".to_string(), "tag2".to_string(), "tag3".to_string()];
        
        assert_eq!(selector.select(&tags), vec!["tag1"]);
        assert_eq!(selector.select(&tags), vec!["tag2"]);
        assert_eq!(selector.select(&tags), vec!["tag3"]);
        assert_eq!(selector.select(&tags), vec!["tag1"]);
    }
}
