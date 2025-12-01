use crate::common::CoreResult;
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{
    accept_async, connect_async, tungstenite::Message, WebSocketStream,
};
use url::Url;

/// WebSocket transport configuration
#[derive(Debug, Clone)]
pub struct WebSocketConfig {
    /// WebSocket path
    pub path: String,
    
    /// Additional headers
    pub headers: HashMap<String, String>,
    
    /// Accept proxy protocol
    pub accept_proxy_protocol: bool,
    
    /// Maximum message size
    pub max_message_size: Option<usize>,
    
    /// Maximum frame size
    pub max_frame_size: Option<usize>,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            headers: HashMap::new(),
            accept_proxy_protocol: false,
            max_message_size: Some(64 * 1024 * 1024), // 64MB
            max_frame_size: Some(16 * 1024 * 1024),   // 16MB
        }
    }
}

/// WebSocket transport implementation
pub struct WebSocketTransport {
    config: WebSocketConfig,
}

impl WebSocketTransport {
    pub fn new(config: WebSocketConfig) -> Self {
        Self { config }
    }
    
    /// Create a WebSocket listener
    pub async fn listen(&self, addr: SocketAddr) -> CoreResult<WebSocketListener> {
        let tcp_listener = TcpListener::bind(addr).await?;
        tracing::info!("WebSocket transport listening on {}", addr);
        
        Ok(WebSocketListener {
            tcp_listener,
            config: self.config.clone(),
        })
    }
    
    /// Connect to a WebSocket server
    pub async fn connect(&self, url: &str) -> CoreResult<WebSocketStream<TcpStream>> {
        let url = Url::parse(url)
            .map_err(|e| crate::common::CoreError::InvalidConfiguration(
                format!("Invalid WebSocket URL: {}", e)
            ))?;
        
        let (ws_stream, _response) = connect_async(url).await
            .map_err(|e| crate::common::CoreError::NetworkError(
                format!("WebSocket connection failed: {}", e)
            ))?;
        
        Ok(ws_stream.into())
    }
    
    /// Upgrade a TCP connection to WebSocket
    pub async fn upgrade(&self, stream: TcpStream) -> CoreResult<WebSocketStream<TcpStream>> {
        let ws_stream = accept_async(stream).await
            .map_err(|e| crate::common::CoreError::ProtocolError(
                format!("WebSocket upgrade failed: {}", e)
            ))?;
        
        Ok(ws_stream)
    }
}

/// WebSocket listener wrapper
pub struct WebSocketListener {
    tcp_listener: TcpListener,
    config: WebSocketConfig,
}

impl WebSocketListener {
    /// Accept incoming WebSocket connections
    pub async fn accept(&self) -> CoreResult<(WebSocketStream<TcpStream>, SocketAddr)> {
        let (tcp_stream, addr) = self.tcp_listener.accept().await?;
        
        let ws_stream = accept_async(tcp_stream).await
            .map_err(|e| crate::common::CoreError::ProtocolError(
                format!("WebSocket upgrade failed: {}", e)
            ))?;
        
        Ok((ws_stream, addr))
    }
    
    /// Get the local address
    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        Ok(self.tcp_listener.local_addr()?)
    }
}

/// WebSocket message wrapper for easier handling
#[derive(Debug, Clone)]
pub enum WsMessage {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close,
}

impl From<Message> for WsMessage {
    fn from(msg: Message) -> Self {
        match msg {
            Message::Text(text) => WsMessage::Text(text),
            Message::Binary(data) => WsMessage::Binary(data),
            Message::Ping(data) => WsMessage::Ping(data),
            Message::Pong(data) => WsMessage::Pong(data),
            Message::Close(_) => WsMessage::Close,
            Message::Frame(_) => WsMessage::Close, // Treat raw frames as close
        }
    }
}

impl From<WsMessage> for Message {
    fn from(msg: WsMessage) -> Self {
        match msg {
            WsMessage::Text(text) => Message::Text(text),
            WsMessage::Binary(data) => Message::Binary(data),
            WsMessage::Ping(data) => Message::Ping(data),
            WsMessage::Pong(data) => Message::Pong(data),
            WsMessage::Close => Message::Close(None),
        }
    }
}

/// WebSocket connection wrapper
pub struct WebSocketConnection {
    stream: WebSocketStream<TcpStream>,
    remote_addr: SocketAddr,
}

impl WebSocketConnection {
    pub fn new(stream: WebSocketStream<TcpStream>, remote_addr: SocketAddr) -> Self {
        Self { stream, remote_addr }
    }
    
    /// Send a message
    pub async fn send(&mut self, message: WsMessage) -> CoreResult<()> {
        use futures::SinkExt;
        
        self.stream.send(message.into()).await
            .map_err(|e| crate::common::CoreError::NetworkError(
                format!("Failed to send WebSocket message: {}", e)
            ))?;
        
        Ok(())
    }
    
    /// Receive a message
    pub async fn receive(&mut self) -> CoreResult<Option<WsMessage>> {
        use futures::StreamExt;
        
        match self.stream.next().await {
            Some(Ok(message)) => Ok(Some(message.into())),
            Some(Err(e)) => Err(crate::common::CoreError::NetworkError(
                format!("Failed to receive WebSocket message: {}", e)
            )),
            None => Ok(None), // Connection closed
        }
    }
    
    /// Close the connection
    pub async fn close(&mut self) -> CoreResult<()> {
        use futures::SinkExt;
        
        self.stream.close(None).await
            .map_err(|e| crate::common::CoreError::NetworkError(
                format!("Failed to close WebSocket connection: {}", e)
            ))?;
        
        Ok(())
    }
    
    /// Get remote address
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    
    #[test]
    fn test_websocket_config() {
        let config = WebSocketConfig::default();
        assert_eq!(config.path, "/");
        assert!(config.headers.is_empty());
        assert!(!config.accept_proxy_protocol);
        assert_eq!(config.max_message_size, Some(64 * 1024 * 1024));
        assert_eq!(config.max_frame_size, Some(16 * 1024 * 1024));
    }
    
    #[tokio::test]
    async fn test_websocket_transport() {
        let config = WebSocketConfig::default();
        let transport = WebSocketTransport::new(config);
        
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        let listener = transport.listen(addr).await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        
        assert!(local_addr.port() > 0);
    }
    
    #[test]
    fn test_ws_message_conversion() {
        let text_msg = WsMessage::Text("hello".to_string());
        let tungstenite_msg: Message = text_msg.clone().into();
        let converted_back: WsMessage = tungstenite_msg.into();
        
        match (text_msg, converted_back) {
            (WsMessage::Text(original), WsMessage::Text(converted)) => {
                assert_eq!(original, converted);
            }
            _ => panic!("Message conversion failed"),
        }
    }
    
    #[test]
    fn test_websocket_connection() {
        // This test would require a real WebSocket connection
        // For now, just test that the types compile correctly
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        
        // Create a mock connection (this won't actually work without a real stream)
        // let connection = WebSocketConnection::new(stream, addr);
        // assert_eq!(connection.remote_addr(), addr);
    }
}