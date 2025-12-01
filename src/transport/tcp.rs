use crate::common::CoreResult;
use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};

/// TCP transport configuration
#[derive(Debug, Clone)]
pub struct TcpConfig {
    /// Accept proxy protocol
    pub accept_proxy_protocol: bool,
    
    /// TCP no delay
    pub no_delay: bool,
    
    /// TCP keep alive
    pub keep_alive: Option<std::time::Duration>,
    
    /// Socket mark (Linux only)
    pub mark: Option<u32>,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            accept_proxy_protocol: false,
            no_delay: true,
            keep_alive: Some(std::time::Duration::from_secs(30)),
            mark: None,
        }
    }
}

/// TCP transport implementation
pub struct TcpTransport {
    config: TcpConfig,
}

impl TcpTransport {
    pub fn new(config: TcpConfig) -> Self {
        Self { config }
    }
    
    /// Create a TCP listener
    pub async fn listen(&self, addr: SocketAddr) -> CoreResult<TcpListener> {
        let listener = TcpListener::bind(addr).await?;
        tracing::info!("TCP transport listening on {}", addr);
        Ok(listener)
    }
    
    /// Connect to a remote address
    pub async fn connect(&self, addr: SocketAddr) -> CoreResult<TcpStream> {
        let stream = TcpStream::connect(addr).await?;
        self.configure_stream(&stream).await?;
        Ok(stream)
    }
    
    /// Configure a TCP stream with transport settings
    pub async fn configure_stream(&self, stream: &TcpStream) -> CoreResult<()> {
        // Set TCP_NODELAY
        if let Err(e) = stream.set_nodelay(self.config.no_delay) {
            tracing::warn!("Failed to set TCP_NODELAY: {}", e);
        }
        
        // Set keep alive
        if let Some(duration) = self.config.keep_alive {
            use std::os::fd::{AsRawFd, FromRawFd};
            let socket = unsafe { socket2::Socket::from_raw_fd(stream.as_raw_fd()) };
            let keep_alive = socket2::TcpKeepalive::new()
                .with_time(duration)
                .with_interval(duration);
            
            if let Err(e) = socket.set_tcp_keepalive(&keep_alive) {
                tracing::warn!("Failed to set TCP keep alive: {}", e);
            }
        }
        
        // Set socket mark (Linux only)
        #[cfg(target_os = "linux")]
        if let Some(mark) = self.config.mark {
            use std::os::fd::{AsRawFd, FromRawFd};
            let socket = unsafe { socket2::Socket::from_raw_fd(stream.as_raw_fd()) };
            if let Err(e) = socket.set_mark(mark) {
                tracing::warn!("Failed to set socket mark: {}", e);
            }
        }
        
        Ok(())
    }
}

/// TCP connection acceptor
pub struct TcpAcceptor {
    listener: TcpListener,
    transport: TcpTransport,
}

impl TcpAcceptor {
    pub fn new(listener: TcpListener, transport: TcpTransport) -> Self {
        Self { listener, transport }
    }
    
    /// Accept incoming connections
    pub async fn accept(&self) -> CoreResult<(TcpStream, SocketAddr)> {
        let (stream, addr) = self.listener.accept().await?;
        self.transport.configure_stream(&stream).await?;
        Ok((stream, addr))
    }
    
    /// Get the local address
    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    
    #[tokio::test]
    async fn test_tcp_transport() {
        let config = TcpConfig::default();
        let transport = TcpTransport::new(config);
        
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        let listener = transport.listen(addr).await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        
        // Test connection
        let connect_task = tokio::spawn(async move {
            transport.connect(local_addr).await
        });
        
        let accept_task = tokio::spawn(async move {
            listener.accept().await
        });
        
        let (connect_result, accept_result) = tokio::join!(connect_task, accept_task);
        
        assert!(connect_result.unwrap().is_ok());
        assert!(accept_result.unwrap().is_ok());
    }
    
    #[tokio::test]
    async fn test_tcp_acceptor() {
        let config = TcpConfig::default();
        let transport = TcpTransport::new(config.clone());
        
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        let listener = transport.listen(addr).await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        
        let acceptor = TcpAcceptor::new(listener, TcpTransport::new(config));
        assert_eq!(acceptor.local_addr().unwrap(), local_addr);
        
        // Test accepting a connection
        let connect_task = tokio::spawn(async move {
            TcpStream::connect(local_addr).await
        });
        
        let accept_task = tokio::spawn(async move {
            acceptor.accept().await
        });
        
        let (connect_result, accept_result) = tokio::join!(connect_task, accept_task);
        
        assert!(connect_result.unwrap().is_ok());
        assert!(accept_result.unwrap().is_ok());
    }
}