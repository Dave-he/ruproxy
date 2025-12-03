use crate::common::{CoreResult, CoreError};
use crate::config::{Config, InboundConfig, OutboundConfig, RoutingConfig, RoutingRule, StreamSettings, TlsSettings, WsSettings, TcpSettings, SniffingConfig};

pub fn from_singbox_json(json: &str) -> CoreResult<Config> {
    let v: serde_json::Value = serde_json::from_str(json)?;
    let mut cfg = Config::default();

    if let Some(inbounds) = v.get("inbounds").and_then(|x| x.as_array()) {
        for ib in inbounds {
            let ty = ib.get("type").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let tag = ib.get("tag").and_then(|x| x.as_str()).map(|s| s.to_string());
            let listen = ib.get("listen").and_then(|x| x.as_str()).map(|s| s.to_string());
            let port = ib.get("listen_port").and_then(|x| x.as_u64()).unwrap_or(0) as u16;
            let settings = ib.get("options").cloned();
            let mut stream_settings: Option<StreamSettings> = None;
            if let Some(transport) = ib.get("transport") {
                let network = transport.get("type").and_then(|x| x.as_str()).map(|s| s.to_string());
                let mut tls_settings: Option<TlsSettings> = None;
                if let Some(tls) = transport.get("tls").and_then(|x| x.as_object()) {
                    let enabled = tls.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false);
                    if enabled {
                        tls_settings = Some(TlsSettings {
                            server_name: tls.get("server_name").and_then(|x| x.as_str()).map(|s| s.to_string()),
                            allow_insecure: tls.get("insecure").and_then(|x| x.as_bool()),
                            certificate_file: tls.get("certificate_file").and_then(|x| x.as_str()).map(|s| s.to_string()),
                            key_file: tls.get("key_file").and_then(|x| x.as_str()).map(|s| s.to_string()),
                            certificates: None,
                        });
                    }
                }
                let mut ws_settings: Option<WsSettings> = None;
                if let Some(ws) = transport.get("ws").and_then(|x| x.as_object()) {
                    ws_settings = Some(WsSettings {
                        path: ws.get("path").and_then(|x| x.as_str()).map(|s| s.to_string()),
                        headers: None,
                        accept_proxy_protocol: ws.get("accept_proxy_protocol").and_then(|x| x.as_bool()),
                    });
                }
                let mut tcp_settings: Option<TcpSettings> = None;
                if let Some(tcp) = transport.get("tcp").and_then(|x| x.as_object()) {
                    tcp_settings = Some(TcpSettings {
                        accept_proxy_protocol: tcp.get("accept_proxy_protocol").and_then(|x| x.as_bool()),
                        header: tcp.get("header").cloned(),
                    });
                }
                let mut http_settings: Option<crate::config::HttpSettings> = None;
                if let Some(http) = transport.get("http").and_then(|x| x.as_object()) {
                    http_settings = Some(crate::config::HttpSettings {
                        host: http.get("host").and_then(|x| x.as_array()).map(|xs| xs.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()),
                        path: http.get("path").and_then(|x| x.as_str()).map(|s| s.to_string()),
                        read_timeout: http.get("read_timeout").and_then(|x| x.as_u64()),
                        read_idle_timeout: http.get("read_idle_timeout").and_then(|x| x.as_u64()),
                        health_check_timeout: http.get("health_check_timeout").and_then(|x| x.as_u64()),
                    });
                }
                stream_settings = Some(StreamSettings {
                    network,
                    security: tls_settings.as_ref().map(|_| "tls".to_string()),
                    tls_settings,
                    tcp_settings,
                    ws_settings,
                    http_settings,
                    socket_settings: None,
                });
            }
            let sniffing = ib.get("sniff").and_then(|x| x.as_object()).map(|sn| SniffingConfig {
                enabled: sn.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false),
                dest_override: sn.get("dest_override").and_then(|x| x.as_array()).map(|xs| xs.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()),
                metadata_only: sn.get("metadata_only").and_then(|x| x.as_bool()),
            });
            cfg.inbounds.push(InboundConfig { tag, listen, port, protocol: ty, settings, stream_settings, sniffing });
        }
    }

    if let Some(outbounds) = v.get("outbounds").and_then(|x| x.as_array()) {
        for ob in outbounds {
            let ty = ob.get("type").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let tag = ob.get("tag").and_then(|x| x.as_str()).map(|s| s.to_string());
            let settings = ob.get("options").cloned();
            let mut stream_settings: Option<StreamSettings> = None;
            if let Some(transport) = ob.get("transport") {
                let network = transport.get("type").and_then(|x| x.as_str()).map(|s| s.to_string());
                let mut tls_settings: Option<TlsSettings> = None;
                if let Some(tls) = transport.get("tls").and_then(|x| x.as_object()) {
                    let enabled = tls.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false);
                    if enabled {
                        tls_settings = Some(TlsSettings {
                            server_name: tls.get("server_name").and_then(|x| x.as_str()).map(|s| s.to_string()),
                            allow_insecure: tls.get("insecure").and_then(|x| x.as_bool()),
                            certificate_file: tls.get("certificate_file").and_then(|x| x.as_str()).map(|s| s.to_string()),
                            key_file: tls.get("key_file").and_then(|x| x.as_str()).map(|s| s.to_string()),
                            certificates: None,
                        });
                    }
                }
                let mut ws_settings: Option<WsSettings> = None;
                if let Some(ws) = transport.get("ws").and_then(|x| x.as_object()) {
                    ws_settings = Some(WsSettings {
                        path: ws.get("path").and_then(|x| x.as_str()).map(|s| s.to_string()),
                        headers: None,
                        accept_proxy_protocol: ws.get("accept_proxy_protocol").and_then(|x| x.as_bool()),
                    });
                }
                let mut tcp_settings: Option<TcpSettings> = None;
                if let Some(tcp) = transport.get("tcp").and_then(|x| x.as_object()) {
                    tcp_settings = Some(TcpSettings {
                        accept_proxy_protocol: tcp.get("accept_proxy_protocol").and_then(|x| x.as_bool()),
                        header: tcp.get("header").cloned(),
                    });
                }
                let mut http_settings: Option<crate::config::HttpSettings> = None;
                if let Some(http) = transport.get("http").and_then(|x| x.as_object()) {
                    http_settings = Some(crate::config::HttpSettings {
                        host: http.get("host").and_then(|x| x.as_array()).map(|xs| xs.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()),
                        path: http.get("path").and_then(|x| x.as_str()).map(|s| s.to_string()),
                        read_timeout: http.get("read_timeout").and_then(|x| x.as_u64()),
                        read_idle_timeout: http.get("read_idle_timeout").and_then(|x| x.as_u64()),
                        health_check_timeout: http.get("health_check_timeout").and_then(|x| x.as_u64()),
                    });
                }
                stream_settings = Some(StreamSettings {
                    network,
                    security: tls_settings.as_ref().map(|_| "tls".to_string()),
                    tls_settings,
                    tcp_settings,
                    ws_settings,
                    http_settings,
                    socket_settings: None,
                });
            }
            cfg.outbounds.push(OutboundConfig { tag, protocol: ty, settings, stream_settings, proxy_settings: None });
        }
    }

    if let Some(route) = v.get("route") {
        let mut rules = Vec::new();
        if let Some(arr) = route.get("rules").and_then(|x| x.as_array()) {
            for r in arr {
                let tag = r.get("tag").and_then(|x| x.as_str()).map(|s| s.to_string());
                let outbound_tag = r.get("outbound").and_then(|x| x.as_str()).unwrap_or("direct").to_string();
                let domains = r.get("domain").and_then(|x| x.as_array()).map(|xs| xs.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect());
                let ips = r.get("ip").and_then(|x| x.as_array()).map(|xs| xs.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect());
                rules.push(RoutingRule { tag, rule_type: Some("field".to_string()), domain: domains, ip: ips, port: None, source_port: None, network: None, source: None, user: None, inbound_tag: None, protocol: None, attrs: None, outbound_tag, balancer_tag: None });
            }
        }
        cfg.routing = Some(RoutingConfig { domain_strategy: None, rules, balancers: None });
    }

    if cfg.inbounds.is_empty() || cfg.outbounds.is_empty() { return Err(CoreError::InvalidConfiguration("sing-box config missing inbounds/outbounds".to_string())); }
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_in_out() {
        let json = r#"{
            "inbounds": [{"type":"http","tag":"in-http","listen":"127.0.0.1","listen_port":8080}],
            "outbounds": [{"type":"direct","tag":"direct"}],
            "route": {"rules": [{"outbound":"direct","domain":["example.com"]}]}
        }"#;
        let cfg = from_singbox_json(json).unwrap();
        assert_eq!(cfg.inbounds.len(), 1);
        assert_eq!(cfg.outbounds.len(), 1);
        assert!(cfg.routing.is_some());
        assert_eq!(cfg.inbounds[0].protocol, "http");
        assert_eq!(cfg.outbounds[0].protocol, "direct");
        assert_eq!(cfg.inbounds[0].listen.as_deref(), Some("127.0.0.1"));
        assert_eq!(cfg.inbounds[0].port, 8080);
    }

    #[test]
    fn parse_transport_ws_tls() {
        let json = r#"{
            "inbounds": [{
                "type":"socks",
                "listen":"0.0.0.0","listen_port":1080,
                "transport": {
                    "type":"ws",
                    "ws": {"path":"/ws"},
                    "tls": {"enabled": true, "server_name":"test.com", "insecure": true}
                }
            }],
            "outbounds": [{
                "type":"direct","tag":"direct",
                "transport": {"type":"tcp"}
            }]
        }"#;
        let cfg = from_singbox_json(json).unwrap();
        let inbound = &cfg.inbounds[0];
        let ss = inbound.stream_settings.as_ref().unwrap();
        assert_eq!(ss.network.as_deref(), Some("ws"));
        assert_eq!(ss.security.as_deref(), Some("tls"));
        assert_eq!(ss.tls_settings.as_ref().unwrap().server_name.as_deref(), Some("test.com"));
        assert_eq!(ss.ws_settings.as_ref().unwrap().path.as_deref(), Some("/ws"));
        let outbound = &cfg.outbounds[0];
        assert_eq!(outbound.stream_settings.as_ref().unwrap().network.as_deref(), Some("tcp"));
    }

    #[test]
    fn parse_sniffing() {
        let json = r#"{
            "inbounds": [{
                "type":"http","listen":"127.0.0.1","listen_port":8080,
                "sniff": {"enabled": true, "dest_override": ["http", "tls"], "metadata_only": false}
            }],
            "outbounds": [{"type":"direct"}]
        }"#;
        let cfg = from_singbox_json(json).unwrap();
        let sniff = cfg.inbounds[0].sniffing.as_ref().unwrap();
        assert!(sniff.enabled);
        assert_eq!(sniff.dest_override.as_ref().unwrap(), &vec!["http".to_string(), "tls".to_string()]);
        assert_eq!(sniff.metadata_only, Some(false));
    }

    #[test]
    fn error_on_missing_in_out() {
        let json = r#"{ "inbounds": [], "outbounds": [] }"#;
        let err = from_singbox_json(json).unwrap_err();
        match err { CoreError::InvalidConfiguration(_) => {}, _ => panic!("unexpected error") }
    }
}
