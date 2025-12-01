pub mod inbound;
pub mod outbound;
pub mod routing;

use crate::common::{HasType, Runnable, CoreResult};
use std::any::TypeId;

/// Core trait for all features in the proxy system
/// This is equivalent to Xray-core's features.Feature interface
#[async_trait::async_trait]
pub trait Feature: HasType + Runnable + Send + Sync {
    /// Get the feature type for registration
    fn feature_type(&self) -> TypeId {
        self.type_id()
    }
}

/// Blanket implementation for any type that implements HasType and Runnable
#[async_trait::async_trait]
impl<T> Feature for T 
where 
    T: HasType + Runnable + Send + Sync 
{
    fn feature_type(&self) -> TypeId {
        self.type_id()
    }
}

// Re-export commonly used types
pub use inbound::{Handler as InboundHandler, Manager as InboundManager, DefaultManager as DefaultInboundManager};
pub use outbound::{Handler as OutboundHandler, Manager as OutboundManager, DefaultManager as DefaultOutboundManager};
pub use routing::{Router, Route, Context as RoutingContext, DefaultRouter};