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
    inbound_mgr: Option<Arc<inbound::DefaultManager>>,
    outbound_mgr: Option<Arc<outbound::DefaultManager>>,
    router: Option<Arc<routing::DefaultRouter>>,
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
            inbound_mgr: None,
            outbound_mgr: None,
            router: None,
        }
    }
    
    /// Check if the instance is running
    pub fn is_running(&self) -> bool {
        self.running
    }
    
    pub fn inbound_manager(&self) -> Option<Arc<inbound::DefaultManager>> { self.inbound_mgr.clone() }
    pub fn outbound_manager(&self) -> Option<Arc<outbound::DefaultManager>> { self.outbound_mgr.clone() }
    pub fn router(&self) -> Option<Arc<routing::DefaultRouter>> { self.router.clone() }
    
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
            // Ignore duplicates silently
            return Ok(());
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
    let inbound = Arc::new(inbound::DefaultManager::new());
    let outbound = Arc::new(outbound::DefaultManager::new());
    let router = Arc::new(routing::DefaultRouter::new());
    instance.add_feature_arc(inbound.clone())?;
    instance.add_feature_arc(outbound.clone())?;
    instance.add_feature_arc(router.clone())?;
    instance.inbound_mgr = Some(inbound);
    instance.outbound_mgr = Some(outbound);
    instance.router = Some(router);
    
    Ok(instance)
}

/// Helper function to require features from instance
pub fn require_features<F>(instance: &mut Instance, callback: F) -> CoreResult<()>
where
    F: Fn(&[Arc<dyn Feature>]) -> CoreResult<()> + Send + Sync + 'static,
{
    instance.require_features(callback, false)
}

/// Helper function to optionally require features from instance
pub fn optional_features<F>(instance: &mut Instance, callback: F) -> CoreResult<()>
where
    F: Fn(&[Arc<dyn Feature>]) -> CoreResult<()> + Send + Sync + 'static,
{
    instance.require_features(callback, true)
}

#[cfg(test)]
mod tests {}
