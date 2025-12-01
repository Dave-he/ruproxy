use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::common::CoreResult;

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Log configuration
    pub log: Option<LogConfig>,
    
    /// Inbound configurations
    pub inbounds: Vec<InboundConfig>,
    
    /// Outbound configurations
    pub outbounds: Vec<OutboundConfig>,
    
    /// Routing configuration
    pub routing: Option<RoutingConfig>,
    
    /// DNS configuration
    pub dns: Option<DnsConfig>,
    
    /// Policy configuration
    pub policy: Option<PolicyConfig>,
    
    /// Statistics configuration
    pub stats: Option<StatsConfig>,
    
    /// Additional application configurations
    #[serde(default)]
    pub apps: Vec<AppConfig>,
}

/// Log configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// Log level
    pub level: String,
    
    /// Log output file
    pub output: Option<String>,
    
    /// Enable access log
    pub access: Option<String>,
    
    /// Enable error log
    pub error: Option<String>,
}

/// Inbound configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundConfig {
    /// Tag for this inbound
    pub tag: Option<String>,
    
    /// Listen address
    pub listen: Option<String>,
    
    /// Listen port
    pub port: u16,
    
    /// Protocol type
    pub protocol: String,
    
    /// Protocol-specific settings
    pub settings: Option<serde_json::Value>,
    
    /// Stream settings
    pub stream_settings: Option<StreamSettings>,
    
    /// Sniffing settings
    pub sniffing: Option<SniffingConfig>,
}

/// Outbound configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundConfig {
    /// Tag for this outbound
    pub tag: Option<String>,
    
    /// Protocol type
    pub protocol: String,
    
    /// Protocol-specific settings
    pub settings: Option<serde_json::Value>,
    
    /// Stream settings
    pub stream_settings: Option<StreamSettings>,
    
    /// Proxy settings
    pub proxy_settings: Option<ProxySettings>,
}

/// Stream settings for transport layer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamSettings {
    /// Network type (tcp, udp, etc.)
    pub network: Option<String>,
    
    /// Security type (none, tls, etc.)
    pub security: Option<String>,
    
    /// TLS settings
    pub tls_settings: Option<TlsSettings>,
    
    /// TCP settings
    pub tcp_settings: Option<TcpSettings>,
    
    /// WebSocket settings
    pub ws_settings: Option<WsSettings>,
    
    /// HTTP/2 settings
    pub http_settings: Option<HttpSettings>,
    
    /// Socket settings
    pub socket_settings: Option<SocketSettings>,
}

/// TLS settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsSettings {
    /// Server name
    pub server_name: Option<String>,
    
    /// Allow insecure connections
    pub allow_insecure: Option<bool>,
    
    /// Certificate file path
    pub certificate_file: Option<String>,
    
    /// Key file path
    pub key_file: Option<String>,
    
    /// Certificate chain
    pub certificates: Option<Vec<Certificate>>,
}

/// Certificate configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    /// Certificate data
    pub certificate: Vec<String>,
    
    /// Private key data
    pub key: Vec<String>,
    
    /// Usage type
    pub usage: Option<String>,
}

/// TCP settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpSettings {
    /// Accept proxy protocol
    pub accept_proxy_protocol: Option<bool>,
    
    /// Header type
    pub header: Option<serde_json::Value>,
}

/// WebSocket settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsSettings {
    /// WebSocket path
    pub path: Option<String>,
    
    /// Headers
    pub headers: Option<HashMap<String, String>>,
    
    /// Accept proxy protocol
    pub accept_proxy_protocol: Option<bool>,
}

/// HTTP settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpSettings {
    /// Host names
    pub host: Option<Vec<String>>,
    
    /// Path
    pub path: Option<String>,
    
    /// Read timeout
    pub read_timeout: Option<u64>,
    
    /// Read idle timeout
    pub read_idle_timeout: Option<u64>,
    
    /// Health check timeout
    pub health_check_timeout: Option<u64>,
}

/// Socket settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocketSettings {
    /// Mark for socket
    pub mark: Option<u32>,
    
    /// TCP fast open
    pub tcp_fast_open: Option<bool>,
    
    /// TCP no delay
    pub tcp_no_delay: Option<bool>,
    
    /// TCP keep alive interval
    pub tcp_keep_alive_interval: Option<u64>,
}

/// Sniffing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SniffingConfig {
    /// Enable sniffing
    pub enabled: bool,
    
    /// Destination override
    pub dest_override: Option<Vec<String>>,
    
    /// Metadata only
    pub metadata_only: Option<bool>,
}

/// Proxy settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySettings {
    /// Proxy tag
    pub tag: String,
    
    /// Transport layer proxy
    pub transport_layer: Option<bool>,
}

/// Routing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    /// Domain strategy
    pub domain_strategy: Option<String>,
    
    /// Rules
    pub rules: Vec<RoutingRule>,
    
    /// Balancers
    pub balancers: Option<Vec<Balancer>>,
}

/// Routing rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRule {
    /// Rule tag
    pub tag: Option<String>,
    
    /// Rule type
    #[serde(rename = "type")]
    pub rule_type: Option<String>,
    
    /// Domain matching
    pub domain: Option<Vec<String>>,
    
    /// IP matching
    pub ip: Option<Vec<String>>,
    
    /// Port matching
    pub port: Option<String>,
    
    /// Source port matching
    pub source_port: Option<String>,
    
    /// Network matching
    pub network: Option<String>,
    
    /// Source matching
    pub source: Option<Vec<String>>,
    
    /// User matching
    pub user: Option<Vec<String>>,
    
    /// Inbound tag matching
    pub inbound_tag: Option<Vec<String>>,
    
    /// Protocol matching
    pub protocol: Option<Vec<String>>,
    
    /// Attributes matching
    pub attrs: Option<HashMap<String, String>>,
    
    /// Outbound tag
    #[serde(alias = "outboundTag")]
    pub outbound_tag: String,
    
    /// Balancer tag
    pub balancer_tag: Option<String>,
}

/// Load balancer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Balancer {
    /// Balancer tag
    pub tag: String,
    
    /// Selector
    pub selector: Vec<String>,
    
    /// Strategy
    pub strategy: Option<BalancerStrategy>,
}

/// Balancer strategy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalancerStrategy {
    /// Strategy type
    #[serde(rename = "type")]
    pub strategy_type: String,
    
    /// Strategy settings
    pub settings: Option<serde_json::Value>,
}

/// DNS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// DNS servers
    pub servers: Vec<DnsServer>,
    
    /// Hosts
    pub hosts: Option<HashMap<String, String>>,
    
    /// Client IP
    pub client_ip: Option<String>,
    
    /// Query strategy
    pub query_strategy: Option<String>,
    
    /// Disable cache
    pub disable_cache: Option<bool>,
    
    /// Disable fallback
    pub disable_fallback: Option<bool>,
}

/// DNS server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsServer {
    /// Server address
    pub address: String,
    
    /// Server port
    pub port: Option<u16>,
    
    /// Domains
    pub domains: Option<Vec<String>>,
    
    /// Expected IPs
    pub expect_ips: Option<Vec<String>>,
    
    /// Skip fallback
    pub skip_fallback: Option<bool>,
}

/// Policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Levels
    pub levels: Option<HashMap<String, PolicyLevel>>,
    
    /// System policy
    pub system: Option<SystemPolicy>,
}

/// Policy level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyLevel {
    /// Handshake timeout
    pub handshake_timeout: Option<u64>,
    
    /// Connection idle timeout
    pub connection_idle_timeout: Option<u64>,
    
    /// Uplink only
    pub uplink_only: Option<u64>,
    
    /// Downlink only
    pub downlink_only: Option<u64>,
    
    /// Stats user uplink
    pub stats_user_uplink: Option<bool>,
    
    /// Stats user downlink
    pub stats_user_downlink: Option<bool>,
    
    /// Buffer size
    pub buffer_size: Option<u32>,
}

/// System policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemPolicy {
    /// Stats inbound uplink
    pub stats_inbound_uplink: Option<bool>,
    
    /// Stats inbound downlink
    pub stats_inbound_downlink: Option<bool>,
    
    /// Stats outbound uplink
    pub stats_outbound_uplink: Option<bool>,
    
    /// Stats outbound downlink
    pub stats_outbound_downlink: Option<bool>,
}

/// Statistics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsConfig {
    /// Enable stats
    pub enabled: Option<bool>,
}

/// Application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// App type
    #[serde(rename = "type")]
    pub app_type: String,
    
    /// App settings
    pub settings: serde_json::Value,
}

impl Config {
    /// Load configuration from file
    pub fn from_file(path: &str) -> CoreResult<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&content)?;
        Ok(config)
    }
    
    /// Load configuration from JSON string
    pub fn from_json(json: &str) -> CoreResult<Self> {
        let config: Config = serde_json::from_str(json)?;
        Ok(config)
    }
    
    /// Save configuration to file
    pub fn to_file(&self, path: &str) -> CoreResult<()> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
    
    /// Convert to JSON string
    pub fn to_json(&self) -> CoreResult<String> {
        let json = serde_json::to_string_pretty(self)?;
        Ok(json)
    }
    
    /// Validate configuration
    pub fn validate(&self) -> CoreResult<()> {
        // Basic validation
        if self.inbounds.is_empty() {
            return Err(crate::common::CoreError::InvalidConfiguration(
                "At least one inbound is required".to_string()
            ));
        }
        
        if self.outbounds.is_empty() {
            return Err(crate::common::CoreError::InvalidConfiguration(
                "At least one outbound is required".to_string()
            ));
        }
        
        // Validate inbound tags are unique
        let mut inbound_tags = std::collections::HashSet::new();
        for inbound in &self.inbounds {
            if let Some(ref tag) = inbound.tag {
                if !inbound_tags.insert(tag) {
                    return Err(crate::common::CoreError::InvalidConfiguration(
                        format!("Duplicate inbound tag: {}", tag)
                    ));
                }
            }
        }
        
        // Validate outbound tags are unique
        let mut outbound_tags = std::collections::HashSet::new();
        for outbound in &self.outbounds {
            if let Some(ref tag) = outbound.tag {
                if !outbound_tags.insert(tag) {
                    return Err(crate::common::CoreError::InvalidConfiguration(
                        format!("Duplicate outbound tag: {}", tag)
                    ));
                }
            }
        }
        
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            log: Some(LogConfig {
                level: "info".to_string(),
                output: None,
                access: None,
                error: None,
            }),
            inbounds: vec![],
            outbounds: vec![],
            routing: None,
            dns: None,
            policy: None,
            stats: None,
            apps: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let json = config.to_json().unwrap();
        let parsed = Config::from_json(&json).unwrap();
        
        // Basic check that serialization/desion works
        assert_eq!(config.inbounds.len(), parsed.inbounds.len());
        assert_eq!(config.outbounds.len(), parsed.outbounds.len());
    }
    
    #[test]
    fn test_config_validation() {
        let mut config = Config::default();
        
        // Should fail with no inbounds/outbounds
        assert!(config.validate().is_err());
        
        // Add minimal inbound and outbound
        config.inbounds.push(InboundConfig {
            tag: Some("test-in".to_string()),
            listen: Some("127.0.0.1".to_string()),
            port: 8080,
            protocol: "http".to_string(),
            settings: None,
            stream_settings: None,
            sniffing: None,
        });
        
        config.outbounds.push(OutboundConfig {
            tag: Some("test-out".to_string()),
            protocol: "freedom".to_string(),
            settings: None,
            stream_settings: None,
            proxy_settings: None,
        });
        
        // Should pass now
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_outbound_tag_alias() {
        let json = r#"{
            "inbounds": [{"port":8080, "protocol":"direct"}],
            "outbounds": [{"tag":"direct", "protocol":"direct"}],
            "routing": {"rules": [{"type":"field", "outboundTag":"direct"}]}
        }"#;
        let cfg = Config::from_json(json).unwrap();
        assert!(cfg.routing.is_some());
        assert_eq!(cfg.routing.as_ref().unwrap().rules[0].outbound_tag, "direct");
    }
}
