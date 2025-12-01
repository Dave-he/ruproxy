use crate::common::{CoreResult, CoreError};
use crate::config::{Config, InboundConfig, OutboundConfig, RoutingConfig, RoutingRule};

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
            cfg.inbounds.push(InboundConfig { tag, listen, port, protocol: ty, settings, stream_settings: None, sniffing: None });
        }
    }

    if let Some(outbounds) = v.get("outbounds").and_then(|x| x.as_array()) {
        for ob in outbounds {
            let ty = ob.get("type").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let tag = ob.get("tag").and_then(|x| x.as_str()).map(|s| s.to_string());
            let settings = ob.get("options").cloned();
            cfg.outbounds.push(OutboundConfig { tag, protocol: ty, settings, stream_settings: None, proxy_settings: None });
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

