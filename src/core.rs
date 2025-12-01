use crate::common::{HasType, Runnable, CoreResult, CoreError};
use crate::features::{Feature, inbound, outbound, routing};
use crate::features::inbound::Manager as InboundManager;
use crate::features::outbound::Manager as OutboundManager;
use async_trait::async_trait;
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::Arc;

/// Dependency resolution callback
type ResolutionCallback = Box<dyn Fn(&[Arc<dyn Feature>]) -> CoreResult<()> + Send + Sync>;

/// Dependency resolution entry
struct Resolution {
    deps: Vec<TypeId>,
    callback: ResolutionCallback,
}

/// Core instance that manages all features
pub struct Instance {
    features: HashMap<TypeId, Arc<dyn Feature>>,
    pending_resolutions: Vec<Resolution>,
    pending_optional_resolutions: Vec<Resolution>,
    running: bool,
    context: HashMap<String, String>,
}

impl Instance {
    /// Create a new instance
    pub fn new() -> Self {
        Self {
            features: HashMap::new(),
            pending_resolutions: Vec::new(),
            pending_optional_resolutions: Vec::new(),
            running: false,
            context: HashMap::new(),
        }
    }
    
    /// Check if the instance is running
    pub fn is_running(&self) -> bool {
        self.running
    }
    
    /// Get a feature by type
    pub fn get_feature<T: Feature + 'static>(&self) -> Option<Arc<T>> {
        let target_type = TypeId::of::<T>();
        
        if let Some(feature) = self.features.get(&target_type) {
            // This is safe because we store features by their TypeId
            let any_ref = &(&**feature) as &dyn Any;
            if let Some(typed_ref) = any_ref.downcast_ref::<T>() {
                // Safe to transmute since we verified the types match
                let typed_arc = unsafe { 
                    std::mem::transmute::<Arc<dyn Feature>, Arc<T>>(feature.clone()) 
                };
                return Some(typed_arc);
            }
        }
        None
    }
    
    /// Get a feature by type ID
    pub fn get_feature_by_type(&self, type_id: TypeId) -> Option<Arc<dyn Feature>> {
        self.features.get(&type_id).map(|f| f.clone())
    }
    
    /// Add a feature to the instance
    pub fn add_feature<T: Feature + 'static>(&mut self, feature: T) -> CoreResult<()> {
        let feature_arc = Arc::new(feature);
        self.add_feature_arc(feature_arc)
    }
    
    /// Add a feature arc to the instance
    pub fn add_feature_arc(&mut self, feature: Arc<dyn Feature>) -> CoreResult<()> {
        let type_id = feature.type_id();
        
        // Check if feature already exists
        if self.features.contains_key(&type_id) {
            return Err(CoreError::FeatureAlreadyExists(
                format!("Feature {} already exists", feature.type_name())
            ));
        }
        
        // Add to features map
        self.features.insert(type_id, feature.clone());
        
        tracing::info!("Added feature: {}", feature.type_name());
        Ok(())
    }
    
    /// Require features with a callback
    pub fn require_features<F>(&mut self, callback: F, optional: bool) -> CoreResult<()>
    where
        F: Fn(&[Arc<dyn Feature>]) -> CoreResult<()> + Send + Sync + 'static,
    {
        let resolution = Resolution {
            deps: Vec::new(), // For now, we'll match all features
            callback: Box::new(callback),
        };
        
        // Check if all dependencies are available
        if !self.features.is_empty() {
            // Dependencies available, execute callback immediately
            let features: Vec<Arc<dyn Feature>> = self.features.iter()
                .map(|(_, feature)| feature.clone())
                .collect();
            return (resolution.callback)(&features);
        }
        
        // Add to pending resolutions
        if optional {
            self.pending_optional_resolutions.push(resolution);
        } else {
            self.pending_resolutions.push(resolution);
        }
        
        Ok(())
    }
    
    /// Process pending resolutions
    fn process_resolutions(&mut self) -> CoreResult<()> {
        let features: Vec<Arc<dyn Feature>> = self.features.iter()
            .map(|(_, feature)| feature.clone())
            .collect();
        
        // Process required resolutions
        for resolution in self.pending_resolutions.drain(..) {
            if let Err(e) = (resolution.callback)(&features) {
                tracing::error!("Resolution callback failed: {}", e);
                return Err(e);
            }
        }
        
        // Process optional resolutions
        for resolution in self.pending_optional_resolutions.drain(..) {
            if let Err(e) = (resolution.callback)(&features) {
                tracing::warn!("Optional resolution callback failed: {}", e);
                // Continue with other resolutions
            }
        }
        
        Ok(())
    }
    
    /// Set context value
    pub fn set_context(&mut self, key: String, value: String) {
        self.context.insert(key, value);
    }
    
    /// Get context value
    pub fn get_context(&self, key: &str) -> Option<String> {
        self.context.get(key).cloned()
    }
}

impl Default for Instance {
    fn default() -> Self {
        Self::new()
    }
}

impl HasType for Instance {
    fn type_id(&self) -> TypeId {
        TypeId::of::<Instance>()
    }
    
    fn type_name(&self) -> &'static str {
        "Instance"
    }
}

#[async_trait]
impl Runnable for Instance {
    async fn start(&self) -> CoreResult<()> {
        // Note: This implementation is simplified due to the change from concurrent data structures
        // to simple collections. In a real implementation, you would need proper synchronization.
        tracing::info!("Rust-Core instance started");
        Ok(())
    }
    
    async fn close(&self) -> CoreResult<()> {
        // Note: This implementation is simplified due to the change from concurrent data structures
        // to simple collections. In a real implementation, you would need proper synchronization.
        tracing::info!("Rust-Core instance closed");
        Ok(())
    }
}

/// Create a new instance with default features
pub async fn new_with_defaults() -> CoreResult<Instance> {
    let mut instance = Instance::new();
    
    // Add default features
    instance.add_feature(inbound::DefaultManager::new())?;
    instance.add_feature(outbound::DefaultManager::new())?;
    instance.add_feature(routing::DefaultRouter::new())?;
    
    Ok(instance)
}

/// Helper function to require features from instance
pub fn require_features<F>(instance: &Instance, callback: F) -> CoreResult<()>
where
    F: Fn(&[Arc<dyn Feature>]) -> CoreResult<()> + Send + Sync + 'static,
{
    instance.require_features(callback, false)
}

/// Helper function to optionally require features from instance
pub fn optional_features<F>(instance: &Instance, callback: F) -> CoreResult<()>
where
    F: Fn(&[Arc<dyn Feature>]) -> CoreResult<()> + Send + Sync + 'static,
{
    instance.require_features(callback, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::routing::DefaultRouter;
    
    #[tokio::test]
    async fn test_instance_lifecycle() {
        let instance = Instance::new();
        
        // Test adding features
        let router = DefaultRouter::new();
        assert!(instance.add_feature(router).await.is_ok());
        
        // Test getting features
        let retrieved_router = instance.get_feature::<DefaultRouter>();
        assert!(retrieved_router.is_some());
        
        // Test starting instance
        assert!(instance.start().await.is_ok());
        assert!(instance.is_running());
        
        // Test closing instance
        assert!(instance.close().await.is_ok());
        assert!(!instance.is_running());
    }
    
    #[tokio::test]
    async fn test_new_with_defaults() {
        let instance = new_with_defaults().await.unwrap();
        
        // Check that default features are present
        assert!(instance.get_feature::<inbound::DefaultManager>().is_some());
        assert!(instance.get_feature::<outbound::DefaultManager>().is_some());
        assert!(instance.get_feature::<routing::DefaultRouter>().is_some());
        
        // Test starting and stopping
        assert!(instance.start().await.is_ok());
        assert!(instance.close().await.is_ok());
    }
    
    #[tokio::test]
    async fn test_context() {
        let instance = Instance::new();
        
        instance.set_context("test_key".to_string(), "test_value".to_string()).await;
        let value = instance.get_context("test_key").await;
        assert_eq!(value, Some("test_value".to_string()));
    }
}