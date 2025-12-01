use anyhow::Result;
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;

/// Core error types for the proxy system
#[derive(Error, Debug)]
pub enum CoreError {
    #[error("Feature not found: {0}")]
    FeatureNotFound(String),
    
    #[error("Feature already exists: {0}")]
    FeatureAlreadyExists(String),
    
    #[error("Dependency resolution failed: {0}")]
    DependencyResolutionFailed(String),
    
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Protocol error: {0}")]
    ProtocolError(String),
    
    #[error("IO error: {source}")]
    IoError {
        #[from]
        source: std::io::Error,
    },
    
    #[error("Serialization error: {source}")]
    SerializationError {
        #[from]
        source: serde_json::Error,
    },
}

/// Result type alias for core operations
pub type CoreResult<T> = Result<T, CoreError>;

/// Common trait for objects that have a type identifier
pub trait HasType: Send + Sync {
    /// Returns the type identifier for this object
    fn type_id(&self) -> TypeId;
    
    /// Returns a string representation of the type
    fn type_name(&self) -> &'static str;
}

/// Common trait for objects that can be started and stopped
#[async_trait::async_trait]
pub trait Runnable: Send + Sync {
    /// Start the object
    async fn start(&self) -> CoreResult<()>;
    
    /// Stop the object and clean up resources
    async fn close(&self) -> CoreResult<()>;
}

/// Common trait for objects that can be closed
#[async_trait::async_trait]
pub trait Closable: Send + Sync {
    /// Close the object and release resources
    async fn close(&self) -> CoreResult<()>;
}

/// Trait for objects that can be interrupted
pub trait Interruptible: Send + Sync {
    /// Interrupt the object's operation
    fn interrupt(&self);
}

/// Helper function to close an object if it implements Closable
pub async fn close_if_closable(obj: &dyn Any) -> CoreResult<()> {
    // Note: This function is currently not implementable due to Rust's type system limitations
    // with trait objects and downcasting. Consider using a different approach.
    Ok(())
}

/// Helper function to interrupt an object
pub async fn interrupt_if_possible(obj: &dyn Any) -> CoreResult<()> {
    // Note: This function is currently not implementable due to Rust's type system limitations
    // with trait objects and downcasting. Consider using a different approach.
    Ok(())
}

/// Chained closable that can close multiple objects
pub struct ChainedClosable {
    closables: Vec<Arc<dyn Closable>>,
}

impl ChainedClosable {
    pub fn new() -> Self {
        Self {
            closables: Vec::new(),
        }
    }
    
    pub fn add<T: Closable + 'static>(&mut self, closable: Arc<T>) {
        self.closables.push(closable);
    }
}

#[async_trait::async_trait]
impl Closable for ChainedClosable {
    async fn close(&self) -> CoreResult<()> {
        let mut errors = Vec::new();
        
        for closable in &self.closables {
            if let Err(e) = closable.close().await {
                errors.push(e);
            }
        }
        
        if errors.is_empty() {
            Ok(())
        } else {
            Err(CoreError::DependencyResolutionFailed(
                format!("Failed to close {} objects", errors.len())
            ))
        }
    }
}

impl Default for ChainedClosable {
    fn default() -> Self {
        Self::new()
    }
}

/// Type registry for managing type information
pub struct TypeRegistry {
    types: HashMap<TypeId, &'static str>,
}

impl TypeRegistry {
    pub fn new() -> Self {
        Self {
            types: HashMap::new(),
        }
    }
    
    pub fn register<T: 'static>(&mut self, name: &'static str) {
        self.types.insert(TypeId::of::<T>(), name);
    }
    
    pub fn get_name(&self, type_id: TypeId) -> Option<&'static str> {
        self.types.get(&type_id).copied()
    }
}

impl Default for TypeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Macro to implement HasType for a type
#[macro_export]
macro_rules! impl_has_type {
    ($type:ty) => {
        impl $crate::common::HasType for $type {
            fn type_id(&self) -> std::any::TypeId {
                std::any::TypeId::of::<$type>()
            }
            
            fn type_name(&self) -> &'static str {
                std::any::type_name::<$type>()
            }
        }
    };
}

/// Macro to implement basic Runnable for a type
#[macro_export]
macro_rules! impl_runnable {
    ($type:ty) => {
        #[async_trait::async_trait]
        impl $crate::common::Runnable for $type {
            async fn start(&self) -> $crate::common::CoreResult<()> {
                Ok(())
            }
            
            async fn close(&self) -> $crate::common::CoreResult<()> {
                Ok(())
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    
    struct TestType;
    impl_has_type!(TestType);
    impl_runnable!(TestType);
    
    #[tokio::test]
    async fn test_has_type() {
        let test_obj = TestType;
        assert_eq!(test_obj.type_id(), TypeId::of::<TestType>());
        assert_eq!(test_obj.type_name(), "rust_core::common::tests::TestType");
    }
    
    #[tokio::test]
    async fn test_runnable() {
        let test_obj = TestType;
        assert!(test_obj.start().await.is_ok());
        assert!(test_obj.close().await.is_ok());
    }
    
    #[tokio::test]
    async fn test_chained_closable() {
        let mut chain = ChainedClosable::new();
        let test_obj = Arc::new(TestType);
        chain.add(test_obj);
        assert!(chain.close().await.is_ok());
    }
}