use crate::common::CoreResult;
use async_trait::async_trait;
use rustls::{ClientConfig, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};

/// TLS transport configuration
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Server name for client connections
    pub server_name: Option<String>,
    
    /// Allow insecure connections
    pub allow_insecure: bool,
    
    /// Certificate chain (PEM format)
    pub certificates: Vec<String>,
    
    /// Private key (PEM format)
    pub private_key: Option<String>,
    
    /// ALPN protocols
    pub alpn_protocols: Vec<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            server_name: None,
            allow_insecure: false,
            certificates: Vec::new(),
            private_key: None,
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
        }
    }
}

/// TLS transport implementation
pub struct TlsTransport {
    config: TlsConfig,
    client_config: Option<Arc<ClientConfig>>,
    server_config: Option<Arc<ServerConfig>>,
}

impl TlsTransport {
    pub fn new(config: TlsConfig) -> CoreResult<Self> {
        let client_config = Self::build_client_config(&config)?;
        let server_config = Self::build_server_config(&config)?;
        
        Ok(Self {
            config,
            client_config,
            server_config,
        })
    }
    
    /// Build client TLS configuration
    fn build_client_config(config: &TlsConfig) -> CoreResult<Option<Arc<ClientConfig>>> {
        let mut client_config = if config.allow_insecure {
            ClientConfig::builder()
                .with_safe_defaults()
                .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
                .with_no_client_auth()
        } else {
            let mut root_store = rustls::RootCertStore::empty();
            root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
                rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            }));
            
            ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };
        
        // Set ALPN protocols
        if !config.alpn_protocols.is_empty() {
            let alpn: Vec<Vec<u8>> = config.alpn_protocols
                .iter()
                .map(|p| p.as_bytes().to_vec())
                .collect();
            client_config.alpn_protocols = alpn;
        }
        
        Ok(Some(Arc::new(client_config)))
    }
    
    /// Build server TLS configuration
    fn build_server_config(config: &TlsConfig) -> CoreResult<Option<Arc<ServerConfig>>> {
        if config.certificates.is_empty() || config.private_key.is_none() {
            return Ok(None);
        }
        
        // Parse certificates
        let mut cert_chain = Vec::new();
        for cert_pem in &config.certificates {
            let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes())?;
            for cert in certs {
                cert_chain.push(rustls::Certificate(cert));
            }
        }
        
        // Parse private key
        let private_key = config.private_key.as_ref().unwrap();
        let mut key_reader = private_key.as_bytes();
        let keys = rustls_pemfile::pkcs8_private_keys(&mut key_reader)?;
        let private_key = keys.into_iter().next()
            .ok_or_else(|| crate::common::CoreError::InvalidConfiguration(
                "No private key found".to_string()
            ))?;
        
        let mut server_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, rustls::PrivateKey(private_key))?;
        
        // Set ALPN protocols
        if !config.alpn_protocols.is_empty() {
            let alpn: Vec<Vec<u8>> = config.alpn_protocols
                .iter()
                .map(|p| p.as_bytes().to_vec())
                .collect();
            server_config.alpn_protocols = alpn;
        }
        
        Ok(Some(Arc::new(server_config)))
    }
    
    /// Create a TLS listener
    pub async fn listen(&self, addr: SocketAddr) -> CoreResult<TlsListener> {
        let tcp_listener = TcpListener::bind(addr).await?;
        
        let server_config = self.server_config.as_ref()
            .ok_or_else(|| crate::common::CoreError::InvalidConfiguration(
                "No server TLS configuration available".to_string()
            ))?;
        
        let acceptor = TlsAcceptor::from(server_config.clone());
        
        Ok(TlsListener {
            tcp_listener,
            acceptor,
        })
    }
    
    /// Connect to a remote address with TLS
    pub async fn connect(&self, addr: SocketAddr, server_name: Option<&str>) -> CoreResult<TlsStream<TcpStream>> {
        let client_config = self.client_config.as_ref()
            .ok_or_else(|| crate::common::CoreError::InvalidConfiguration(
                "No client TLS configuration available".to_string()
            ))?;
        
        let connector = TlsConnector::from(client_config.clone());
        let tcp_stream = TcpStream::connect(addr).await?;
        
        let server_name = server_name
            .or(self.config.server_name.as_deref())
            .unwrap_or("localhost");
        
        let server_name = rustls::ServerName::try_from(server_name)
            .map_err(|e| crate::common::CoreError::InvalidConfiguration(
                format!("Invalid server name: {}", e)
            ))?;
        
        let tls_stream = connector.connect(server_name, tcp_stream).await?;
        Ok(tokio_rustls::TlsStream::Client(tls_stream))
    }
}

/// TLS listener wrapper
pub struct TlsListener {
    tcp_listener: TcpListener,
    acceptor: TlsAcceptor,
}

impl TlsListener {
    /// Accept incoming TLS connections
    pub async fn accept(&self) -> CoreResult<(TlsStream<TcpStream>, SocketAddr)> {
        let (tcp_stream, addr) = self.tcp_listener.accept().await?;
        let tls_stream = self.acceptor.accept(tcp_stream).await?;
        Ok((tokio_rustls::TlsStream::Server(tls_stream), addr))
    }
    
    /// Get the local address
    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        Ok(self.tcp_listener.local_addr()?)
    }
}

/// Insecure certificate verifier for testing
struct InsecureVerifier;

impl rustls::client::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    
    #[test]
    fn test_tls_config() {
        let config = TlsConfig::default();
        assert!(!config.allow_insecure);
        assert!(config.certificates.is_empty());
        assert!(config.private_key.is_none());
        assert_eq!(config.alpn_protocols, vec!["h2", "http/1.1"]);
    }
    
    #[tokio::test]
    async fn test_tls_transport_client_only() {
        let config = TlsConfig {
            allow_insecure: true,
            ..Default::default()
        };
        
        let transport = TlsTransport::new(config).unwrap();
        assert!(transport.client_config.is_some());
        assert!(transport.server_config.is_none());
    }
}
