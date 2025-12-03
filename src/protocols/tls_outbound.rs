use crate::common::{HasType, Runnable, CoreResult};
use crate::features::{Feature, outbound};
use async_trait::async_trait;
use std::any::TypeId;
use std::sync::Arc;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TlsOutboundConfig {
    pub allow_insecure: Option<bool>,
    pub alpn_protocols: Option<Vec<String>>,
    pub server_name: Option<String>,
}

pub struct TlsOutbound {
    tag: String,
    config: TlsOutboundConfig,
    client_config: Arc<rustls::ClientConfig>,
}

impl TlsOutbound {
    pub fn new(tag: String, config: TlsOutboundConfig) -> CoreResult<Self> {
        let allow_insecure = config.allow_insecure.unwrap_or(true);
        let mut client_config = if allow_insecure {
            rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
                .with_no_client_auth()
        } else {
            let mut root_store = rustls::RootCertStore::empty();
            root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
                rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject, ta.spki, ta.name_constraints,
                )
            }));
            rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };
        if let Some(alpn) = &config.alpn_protocols {
            client_config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
        }
        Ok(Self { tag, config, client_config: Arc::new(client_config) })
    }
}

impl HasType for TlsOutbound {
    fn type_id(&self) -> TypeId { TypeId::of::<TlsOutbound>() }
    fn type_name(&self) -> &'static str { "TlsOutbound" }
}

#[async_trait]
impl Runnable for TlsOutbound {
    async fn start(&self) -> CoreResult<()> { Ok(()) }
    async fn close(&self) -> CoreResult<()> { Ok(()) }
}

#[async_trait]
impl outbound::Handler for TlsOutbound {
    fn tag(&self) -> &str { &self.tag }

    async fn dispatch(&self, context: outbound::OutboundContext, mut link: outbound::Link) -> CoreResult<()> {
        let server_name = self.config.server_name.as_deref().or_else(|| context.domain.as_deref()).unwrap_or("localhost");
        let server_name = rustls::ServerName::try_from(server_name).map_err(|e| crate::common::CoreError::InvalidConfiguration(e.to_string()))?;
        let connector = tokio_rustls::TlsConnector::from(self.client_config.clone());
        let tcp = tokio::net::TcpStream::connect(context.destination_addr).await?;
        let tls = connector.connect(server_name, tcp).await?;
        let (mut r2, mut w2) = tokio::io::split(tls);
        let uplink = tokio::spawn(async move { tokio::io::copy(&mut link.reader, &mut w2).await });
        let downlink = tokio::spawn(async move { tokio::io::copy(&mut r2, &mut link.writer).await });
        let _ = tokio::join!(uplink, downlink);
        Ok(())
    }
}

pub fn create_tls_outbound(tag: String, config: TlsOutboundConfig) -> Arc<dyn outbound::Handler> { Arc::new(TlsOutbound::new(tag, config).expect("invalid tls outbound config")) }

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
