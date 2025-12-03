use crate::common::{HasType, Runnable, CoreResult, CoreError};
use crate::features::Feature;
use async_trait::async_trait;
use std::any::TypeId;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

/// Routing context containing request information
#[derive(Debug, Clone)]
pub struct Context {
    pub source_addr: SocketAddr,
    pub destination_addr: SocketAddr,
    pub inbound_tag: String,
    pub user_id: Option<String>,
    pub protocol: String,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub headers: std::collections::HashMap<String, String>,
}

impl Context {
    pub fn new(source_addr: SocketAddr, destination_addr: SocketAddr) -> Self {
        Self {
            source_addr,
            destination_addr,
            inbound_tag: String::new(),
            user_id: None,
            protocol: String::new(),
            domain: None,
            path: None,
            headers: std::collections::HashMap::new(),
        }
    }
    
    pub fn with_inbound_tag(mut self, tag: String) -> Self {
        self.inbound_tag = tag;
        self
    }
    
    pub fn with_protocol(mut self, protocol: String) -> Self {
        self.protocol = protocol;
        self
    }
    
    pub fn with_domain(mut self, domain: String) -> Self {
        self.domain = Some(domain);
        self
    }
}

/// Routing result
#[derive(Debug, Clone)]
pub struct Route {
    pub context: Context,
    pub outbound_tag: String,
    pub outbound_group_tags: Vec<String>,
    pub rule_tag: Option<String>,
}

impl Route {
    pub fn new(context: Context, outbound_tag: String) -> Self {
        Self {
            context,
            outbound_tag,
            outbound_group_tags: Vec::new(),
            rule_tag: None,
        }
    }
    
    pub fn with_group_tags(mut self, tags: Vec<String>) -> Self {
        self.outbound_group_tags = tags;
        self
    }
    
    pub fn with_rule_tag(mut self, tag: String) -> Self {
        self.rule_tag = Some(tag);
        self
    }
}

/// Router trait for making routing decisions
#[async_trait]
pub trait Router: Feature {
    /// Pick a route based on the given context
    async fn pick_route(&self, context: &Context) -> CoreResult<Route>;
    
    /// Add a routing rule
    async fn add_rule(&self, rule: Box<dyn Rule>, should_append: bool) -> CoreResult<()>;
    
    /// Remove a routing rule by tag
    async fn remove_rule(&self, tag: &str) -> CoreResult<()>;
}

/// Type identifier for Router trait
pub fn router_type() -> TypeId {
    TypeId::of::<dyn Router>()
}

/// Routing rule trait
pub trait Rule: Send + Sync {
    /// Check if this rule matches the given context
    fn matches(&self, context: &Context) -> bool;
    
    /// Get the outbound tag for this rule
    fn outbound_tag(&self) -> &str;
    
    /// Get the rule tag for debugging
    fn rule_tag(&self) -> Option<&str> {
        None
    }
}

/// Domain-based routing rule
pub struct DomainRule {
    pub domains: Vec<String>,
    pub outbound_tag: String,
    pub rule_tag: Option<String>,
}

impl DomainRule {
    pub fn new(domains: Vec<String>, outbound_tag: String) -> Self {
        Self {
            domains,
            outbound_tag,
            rule_tag: None,
        }
    }
    
    pub fn with_tag(mut self, tag: String) -> Self {
        self.rule_tag = Some(tag);
        self
    }
}

impl Rule for DomainRule {
    fn matches(&self, context: &Context) -> bool {
        if let Some(ref domain) = context.domain {
            return self.domains.iter().any(|d| {
                domain == d || domain.ends_with(&format!(".{}", d))
            });
        }
        
        // Try to extract domain from destination address
        if let Some(host) = context.headers.get("host") {
            return self.domains.iter().any(|d| {
                host == d || host.ends_with(&format!(".{}", d))
            });
        }
        
        false
    }
    
    fn outbound_tag(&self) -> &str {
        &self.outbound_tag
    }
    
    fn rule_tag(&self) -> Option<&str> {
        self.rule_tag.as_deref()
    }
}

/// IP-based routing rule
pub struct IpRule {
    pub cidrs: Vec<ipnet::IpNet>,
    pub outbound_tag: String,
    pub rule_tag: Option<String>,
}

impl IpRule {
    pub fn new(cidrs: Vec<ipnet::IpNet>, outbound_tag: String) -> Self {
        Self {
            cidrs,
            outbound_tag,
            rule_tag: None,
        }
    }
    
    pub fn with_tag(mut self, tag: String) -> Self {
        self.rule_tag = Some(tag);
        self
    }
}

impl Rule for IpRule {
    fn matches(&self, context: &Context) -> bool {
        let ip = context.destination_addr.ip();
        self.cidrs.iter().any(|cidr| cidr.contains(&ip))
    }
    
    fn outbound_tag(&self) -> &str {
        &self.outbound_tag
    }
    
    fn rule_tag(&self) -> Option<&str> {
        self.rule_tag.as_deref()
    }
}

/// Inbound tag based routing rule
pub struct InboundTagRule {
    pub tags: Vec<String>,
    pub outbound_tag: String,
    pub rule_tag: Option<String>,
}

impl InboundTagRule {
    pub fn new(tags: Vec<String>, outbound_tag: String) -> Self {
        Self { tags, outbound_tag, rule_tag: None }
    }
    pub fn with_tag(mut self, tag: String) -> Self { self.rule_tag = Some(tag); self }
}

impl Rule for InboundTagRule {
    fn matches(&self, context: &Context) -> bool {
        self.tags.iter().any(|t| t == &context.inbound_tag)
    }
    fn outbound_tag(&self) -> &str { &self.outbound_tag }
    fn rule_tag(&self) -> Option<&str> { self.rule_tag.as_deref() }
}

/// Protocol based routing rule
pub struct ProtocolRule {
    pub protocols: Vec<String>,
    pub outbound_tag: String,
    pub rule_tag: Option<String>,
}

impl ProtocolRule {
    pub fn new(protocols: Vec<String>, outbound_tag: String) -> Self {
        Self { protocols, outbound_tag, rule_tag: None }
    }
    pub fn with_tag(mut self, tag: String) -> Self { self.rule_tag = Some(tag); self }
}

impl Rule for ProtocolRule {
    fn matches(&self, context: &Context) -> bool {
        self.protocols.iter().any(|p| p == &context.protocol)
    }
    fn outbound_tag(&self) -> &str { &self.outbound_tag }
    fn rule_tag(&self) -> Option<&str> { self.rule_tag.as_deref() }
}

/// Destination port based routing rule
pub struct PortRule {
    ranges: Vec<(u16,u16)>,
    outbound_tag: String,
    rule_tag: Option<String>,
}

impl PortRule {
    pub fn new(spec: &str, outbound_tag: String) -> Self {
        let mut ranges = Vec::new();
        for part in spec.split(',') {
            let p = part.trim();
            if p.is_empty() { continue; }
            if let Some((a,b)) = p.split_once('-') {
                let s = a.trim().parse::<u16>().unwrap_or(0);
                let e = b.trim().parse::<u16>().unwrap_or(0);
                if s > 0 && e > 0 { ranges.push((s.min(e), s.max(e))); }
            } else {
                if let Ok(v) = p.parse::<u16>() { ranges.push((v,v)); }
            }
        }
        Self { ranges, outbound_tag, rule_tag: None }
    }
    pub fn with_tag(mut self, tag: String) -> Self { self.rule_tag = Some(tag); self }
}

impl Rule for PortRule {
    fn matches(&self, context: &Context) -> bool {
        let port = context.destination_addr.port();
        self.ranges.iter().any(|(s,e)| port >= *s && port <= *e)
    }
    fn outbound_tag(&self) -> &str { &self.outbound_tag }
    fn rule_tag(&self) -> Option<&str> { self.rule_tag.as_deref() }
}

/// Source port based routing rule
pub struct SourcePortRule {
    ranges: Vec<(u16,u16)>,
    outbound_tag: String,
    rule_tag: Option<String>,
}

impl SourcePortRule {
    pub fn new(spec: &str, outbound_tag: String) -> Self {
        let mut ranges = Vec::new();
        for part in spec.split(',') {
            let p = part.trim();
            if p.is_empty() { continue; }
            if let Some((a,b)) = p.split_once('-') {
                let s = a.trim().parse::<u16>().unwrap_or(0);
                let e = b.trim().parse::<u16>().unwrap_or(0);
                if s > 0 && e > 0 { ranges.push((s.min(e), s.max(e))); }
            } else {
                if let Ok(v) = p.parse::<u16>() { ranges.push((v,v)); }
            }
        }
        Self { ranges, outbound_tag, rule_tag: None }
    }
    pub fn with_tag(mut self, tag: String) -> Self { self.rule_tag = Some(tag); self }
}

impl Rule for SourcePortRule {
    fn matches(&self, context: &Context) -> bool {
        let port = context.source_addr.port();
        self.ranges.iter().any(|(s,e)| port >= *s && port <= *e)
    }
    fn outbound_tag(&self) -> &str { &self.outbound_tag }
    fn rule_tag(&self) -> Option<&str> { self.rule_tag.as_deref() }
}

/// Default router implementation
pub struct DefaultRouter {
    rules: parking_lot::RwLock<Vec<Box<dyn Rule>>>,
    default_outbound: parking_lot::RwLock<String>,
}

impl DefaultRouter {
    pub fn new() -> Self {
        Self {
            rules: parking_lot::RwLock::new(Vec::new()),
            default_outbound: parking_lot::RwLock::new("direct".to_string()),
        }
    }
    
    pub fn with_default_outbound(mut self, outbound: String) -> Self {
        *self.default_outbound.write() = outbound;
        self
    }
}

impl Default for DefaultRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl HasType for DefaultRouter {
    fn type_id(&self) -> TypeId {
        router_type()
    }
    
    fn type_name(&self) -> &'static str {
        "DefaultRouter"
    }
}

#[async_trait]
impl Runnable for DefaultRouter {
    async fn start(&self) -> CoreResult<()> {
        tracing::info!("Router started");
        Ok(())
    }
    
    async fn close(&self) -> CoreResult<()> {
        tracing::info!("Router closed");
        Ok(())
    }
}

#[async_trait]
impl Router for DefaultRouter {
    async fn pick_route(&self, context: &Context) -> CoreResult<Route> {
        let rules_guard = self.rules.read();
        for rule in rules_guard.iter() {
            if rule.matches(context) {
                let route = Route::new(context.clone(), rule.outbound_tag().to_string());
                let route = if let Some(tag) = rule.rule_tag() {
                    route.with_rule_tag(tag.to_string())
                } else {
                    route
                };
                return Ok(route);
            }
        }
        
        // No rule matched, use default outbound
        let default_outbound = self.default_outbound.read().clone();
        Ok(Route::new(context.clone(), default_outbound))
    }
    
    async fn add_rule(&self, rule: Box<dyn Rule>, should_append: bool) -> CoreResult<()> {
        let mut rules = self.rules.write();
        
        if should_append {
            rules.push(rule);
        } else {
            rules.insert(0, rule);
        }
        
        tracing::info!("Added routing rule");
        Ok(())
    }
    
    async fn remove_rule(&self, tag: &str) -> CoreResult<()> {
        let mut rules = self.rules.write();
        let initial_len = rules.len();
        
        rules.retain(|rule| {
            rule.rule_tag().map_or(true, |t| t != tag)
        });
        
        if rules.len() < initial_len {
            tracing::info!("Removed routing rule: {}", tag);
            Ok(())
        } else {
            Err(CoreError::FeatureNotFound(format!("Rule not found: {}", tag)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    
    #[tokio::test]
    async fn test_domain_rule() {
        let rule = DomainRule::new(
            vec!["example.com".to_string(), "test.org".to_string()],
            "proxy".to_string(),
        );
        
        let mut context = Context::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 80)),
        );
        
        // Test exact match
        context.domain = Some("example.com".to_string());
        assert!(rule.matches(&context));
        
        // Test subdomain match
        context.domain = Some("sub.example.com".to_string());
        assert!(rule.matches(&context));
        
        // Test no match
        context.domain = Some("other.com".to_string());
        assert!(!rule.matches(&context));
    }
    
    #[tokio::test]
    async fn test_ip_rule() {
        let cidr: ipnet::IpNet = "192.168.0.0/16".parse().unwrap();
        let rule = IpRule::new(vec![cidr], "direct".to_string());
        
        let context1 = Context::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 80)),
        );
        
        let context2 = Context::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 80)),
        );
        
        assert!(rule.matches(&context1));
        assert!(!rule.matches(&context2));
    }
    
    #[tokio::test]
    async fn test_default_router() {
        let router = DefaultRouter::new().with_default_outbound("default".to_string());
        
        let context = Context::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 80)),
        );
        
        // Test default routing
        let route = router.pick_route(&context).await.unwrap();
        assert_eq!(route.outbound_tag, "default");
        
        // Add a rule and test
        let rule = Box::new(DomainRule::new(
            vec!["example.com".to_string()],
            "proxy".to_string(),
        ));
        router.add_rule(rule, true).await.unwrap();
        
        let mut context_with_domain = context.clone();
        context_with_domain.domain = Some("example.com".to_string());
        
        let route = router.pick_route(&context_with_domain).await.unwrap();
        assert_eq!(route.outbound_tag, "proxy");
    }

    #[tokio::test]
    async fn test_additional_rules() {
        let mut context = Context::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127,0,0,1), 5555)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8,8,8,8), 443)),
        ).with_inbound_tag("in-socks".to_string()).with_protocol("socks".to_string());

        let inbound_rule = InboundTagRule::new(vec!["in-socks".to_string()], "proxy".to_string());
        assert!(inbound_rule.matches(&context));
        assert_eq!(inbound_rule.outbound_tag(), "proxy");

        let proto_rule = ProtocolRule::new(vec!["http".to_string(), "socks".to_string()], "proxy".to_string());
        assert!(proto_rule.matches(&context));

        let port_rule = PortRule::new("80,443,8080-8081", "proxy".to_string());
        assert!(port_rule.matches(&context));

        let source_rule = SourcePortRule::new("1024-65535", "proxy".to_string());
        assert!(source_rule.matches(&context));
    }
}
