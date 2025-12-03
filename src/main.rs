use clap::{Parser, Subcommand};
use rust_core::{
    config::Config,
    core::{Instance, new_with_defaults},
    features::{inbound, outbound, routing},
    protocols::{direct, shadowsocks, create_socks_inbound, SocksConfig, create_http_inbound, HttpInboundConfig, create_tcp_forward_inbound, TcpForwardConfig, create_https_inbound, HttpsInboundConfig},
    CoreResult,
};
use rust_core::Runnable;
use rust_core::features::inbound::Manager as InboundManager;
use rust_core::features::outbound::Manager as OutboundManager;
use rust_core::features::Router;
use tokio::net::{TcpListener, UdpSocket};
use std::sync::Arc;
use std::path::PathBuf;
use tracing::{info, error};

#[derive(Parser)]
#[command(name = "rust-core")]
#[command(about = "A high-performance proxy core written in Rust")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the proxy server
    Run {
        /// Configuration file path
        #[arg(short, long, default_value = "config.json")]
        config: PathBuf,
        
        /// Test configuration and exit
        #[arg(short, long)]
        test: bool,
    },
    /// Generate a sample configuration file
    Generate {
        /// Output file path
        #[arg(short, long, default_value = "config.json")]
        output: PathBuf,
    },
    /// Validate configuration file
    Validate {
        /// Configuration file path
        #[arg(short, long, default_value = "config.json")]
        config: PathBuf,
    },
    /// Show version information
    Version,
}

#[tokio::main]
async fn main() -> CoreResult<()> {
    // Initialize tracing
    rust_core::init_tracing();
    
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Run { config, test } => {
            run_server(config, test).await
        }
        Commands::Generate { output } => {
            generate_config(output).await
        }
        Commands::Validate { config } => {
            validate_config(config).await
        }
        Commands::Version => {
            show_version();
            Ok(())
        }
    }
}

async fn run_server(config_path: PathBuf, test_only: bool) -> CoreResult<()> {
    info!("Loading configuration from {:?}", config_path);
    
    let config = Config::from_file(config_path.to_str().unwrap())?;
    config.validate()?;
    
    if test_only {
        info!("Configuration test passed");
        return Ok(());
    }
    
    info!("Starting Rust-Core proxy server");
    
    // Create instance with default features
    let instance = new_with_defaults().await?;
    let inbound_mgr = instance.inbound_manager().expect("Inbound manager not found");
    let outbound_mgr = instance.outbound_manager().expect("Outbound manager not found");
    
    // Configure inbound handlers
    for inbound_config in &config.inbounds {
        let tag = inbound_config.tag.clone().unwrap_or_else(|| {
            format!("inbound-{}", inbound_config.port)
        });
        
        match inbound_config.protocol.as_str() {
            "direct" => {
                let handler = direct::create_direct_inbound(tag);
                inbound_mgr.add_handler(handler).await?;
            }
            "shadowsocks" => {
                if let Some(settings) = &inbound_config.settings {
                    let ss_config: shadowsocks::ShadowsocksConfig = 
                        serde_json::from_value(settings.clone())?;
                    let handler = shadowsocks::create_shadowsocks_inbound(tag, ss_config);
                    inbound_mgr.add_handler(handler).await?;
                }
            }
            "socks" => {
                let cfg = if let Some(settings) = &inbound_config.settings { serde_json::from_value::<SocksConfig>(settings.clone())? } else { SocksConfig { auth: None, udp: None, address: None, port: None } };
                let handler = create_socks_inbound(tag, cfg);
                inbound_mgr.add_handler(handler).await?;
            }
            "http" => {
                let cfg = if let Some(settings) = &inbound_config.settings { serde_json::from_value::<HttpInboundConfig>(settings.clone())? } else { HttpInboundConfig { address: None, port: None } };
                let handler = create_http_inbound(tag, cfg);
                inbound_mgr.add_handler(handler).await?;
            }
            "https" => {
                if let Some(settings) = &inbound_config.settings {
                    let cfg: HttpsInboundConfig = serde_json::from_value(settings.clone())?;
                    let handler = create_https_inbound(tag, cfg);
                    inbound_mgr.add_handler(handler).await?;
                } else {
                    return Err(rust_core::CoreError::InvalidConfiguration(
                        "https inbound requires settings.tls".to_string()
                    ));
                }
            }
            "tcp" => {
                if let Some(settings) = &inbound_config.settings {
                    let cfg: TcpForwardConfig = serde_json::from_value(settings.clone())?;
                    let handler = create_tcp_forward_inbound(tag, cfg);
                    inbound_mgr.add_handler(handler).await?;
                } else {
                    return Err(rust_core::CoreError::InvalidConfiguration(
                        "tcp inbound requires settings { address, port }".to_string()
                    ));
                }
            }
            protocol => {
                error!("Unsupported inbound protocol: {}", protocol);
                return Err(rust_core::CoreError::InvalidConfiguration(
                    format!("Unsupported inbound protocol: {}", protocol)
                ));
            }
        }
    }
    
    // Configure outbound handlers
    for outbound_config in &config.outbounds {
        let tag = outbound_config.tag.clone().unwrap_or_else(|| {
            format!("outbound-{}", outbound_config.protocol)
        });
        
        match outbound_config.protocol.as_str() {
            "direct" | "freedom" => {
                let handler = direct::create_direct_outbound(tag);
                outbound_mgr.add_handler(handler).await?;
            }
            "shadowsocks" => {
                if let Some(settings) = &outbound_config.settings {
                    let ss_config: shadowsocks::ShadowsocksConfig = 
                        serde_json::from_value(settings.clone())?;
                    let handler = shadowsocks::create_shadowsocks_outbound(tag, ss_config);
                    outbound_mgr.add_handler(handler).await?;
                }
            }
            protocol => {
                error!("Unsupported outbound protocol: {}", protocol);
                return Err(rust_core::CoreError::InvalidConfiguration(
                    format!("Unsupported outbound protocol: {}", protocol)
                ));
            }
        }
    }
    
    // Build router from config
    let router = {
        let mut r = routing::DefaultRouter::new();
        if let Some(default) = outbound_mgr.get_default_handler().as_ref().map(|h| h.tag().to_string()) {
            r = r.with_default_outbound(default);
        }
        if let Some(routing_cfg) = &config.routing {
            for rule in &routing_cfg.rules {
                let outbound = rule.outbound_tag.clone();
                if let Some(domains) = &rule.domain {
                    let rr = Box::new(routing::DomainRule::new(domains.clone(), outbound.clone()));
                    let _ = r.add_rule(rr, false).await;
                }
                if let Some(ips) = &rule.ip {
                    let mut cidrs = Vec::new();
                    for s in ips { if let Ok(c) = s.parse::<ipnet::IpNet>() { cidrs.push(c); } }
                    if !cidrs.is_empty() {
                        let rr = Box::new(routing::IpRule::new(cidrs, outbound.clone()));
                        let _ = r.add_rule(rr, false).await;
                    }
                }
            }
        }
        Arc::new(r)
    };

    // Start the instance
    instance.start().await?;
    
    info!("Rust-Core proxy server started successfully");

    // Spawn inbound listeners
    for inbound_config in &config.inbounds {
        let tag = inbound_config.tag.clone().unwrap_or_else(|| format!("inbound-{}", inbound_config.port));
        let addr = format!("{}:{}", inbound_config.listen.as_deref().unwrap_or("0.0.0.0"), inbound_config.port);
        let protocol = inbound_config.protocol.clone();
        if protocol == "udp" {
            let udp_settings = inbound_config.settings.clone().ok_or_else(|| rust_core::CoreError::InvalidConfiguration("udp inbound requires settings { address, port }".to_string()))?;
            #[derive(serde::Deserialize)]
            struct UdpForwardConfig { address: String, port: u16 }
            let cfg: UdpForwardConfig = serde_json::from_value(udp_settings)?;
            let listen_socket = UdpSocket::bind(&addr).await?;
            let remote_addr = tokio::net::lookup_host(format!("{}:{}", cfg.address, cfg.port)).await?
                .next().ok_or_else(|| rust_core::CoreError::NetworkError("UDP resolve failed".to_string()))?;
            let last_client: Arc<parking_lot::RwLock<Option<std::net::SocketAddr>>> = Arc::new(parking_lot::RwLock::new(None));
            let lc = last_client.clone();
            let addr_c = addr.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                loop {
                    match listen_socket.recv_from(&mut buf).await {
                        Ok((n, src)) => {
                            if src == remote_addr {
                                let client_opt = { *lc.read() };
                                if let Some(client) = client_opt {
                                    let _ = listen_socket.send_to(&buf[..n], client).await;
                                }
                            } else {
                                { *lc.write() = Some(src); }
                                let _ = listen_socket.send_to(&buf[..n], remote_addr).await;
                            }
                        }
                        Err(e) => {
                            tracing::error!("UDP accept error on {}: {}", addr_c, e);
                            break;
                        }
                    }
                }
            });
            tracing::info!("Listening UDP inbound {} on {} -> {}", tag, addr, remote_addr);
            continue;
        }

        let listener = TcpListener::bind(&addr).await?;
        let mgr = inbound_mgr.clone();
        let outbound_mgr_cloned = outbound_mgr.clone();
        let addr_c = addr.clone();
        let tag_c = tag.clone();
        let protocol_c = protocol.clone();
        let router_c = router.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        let ictx = inbound::InboundContext::new(peer, peer, protocol_c.clone(), tag_c.clone());
                        match mgr.get_handler(&tag_c).await {
                            Ok(handler) => {
                                if protocol_c == "socks" || protocol_c == "http" || protocol_c == "tcp" || protocol_c == "https" {
                                    match handler.prepare_dispatch(stream, &ictx).await {
                                        Ok((out_ctx, link)) => {
                                            let rctx = routing::Context::new(peer, out_ctx.destination_addr)
                                                .with_inbound_tag(tag_c.clone())
                                                .with_protocol(protocol_c.clone());
                                            let route = router_c.pick_route(&rctx).await.ok();
                                            let ob = route
                                                .and_then(|rt| outbound_mgr_cloned.get_handler(&rt.outbound_tag))
                                                .or_else(|| outbound_mgr_cloned.get_default_handler())
                                                .or_else(|| outbound_mgr_cloned.get_handler("direct"));
                                            if let Some(h) = ob {
                                                if let Err(e) = h.dispatch(out_ctx, link).await {
                                                    tracing::error!("Outbound dispatch error: {}", e);
                                                }
                                            } else {
                                                tracing::error!("No outbound handler available");
                                            }
                                        }
                                        Err(e) => {
                                            tracing::error!("prepare_dispatch error on {}: {}", protocol_c, e);
                                        }
                                    }
                                } else {
                                    if let Err(e) = handler.handle_connection(stream, ictx).await {
                                        tracing::error!("Inbound handle error: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::error!("Inbound handler {} not found: {}", tag_c, e);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Accept error on {}: {}", addr_c, e);
                        break;
                    }
                }
            }
        });
        tracing::info!("Listening inbound {} on {}", tag, addr);
    }
    
    // Wait for shutdown signal
    tokio::signal::ctrl_c().await.map_err(|e| {
        rust_core::CoreError::IoError { source: e }
    })?;
    
    info!("Received shutdown signal, stopping server");
    
    // Stop the instance
    instance.close().await?;
    
    info!("Rust-Core proxy server stopped");
    Ok(())
}

async fn generate_config(output_path: PathBuf) -> CoreResult<()> {
    info!("Generating sample configuration to {:?}", output_path);
    
    let mut config = Config::default();
    
    // Add sample TCP port mapping inbound: listen 127.0.0.1:8080 -> example.com:80
    let tcp_cfg = TcpForwardConfig { address: "example.com".to_string(), port: 80 };
    config.inbounds.push(rust_core::config::InboundConfig {
        tag: Some("tcp-map".to_string()),
        listen: Some("127.0.0.1".to_string()),
        port: 8080,
        protocol: "tcp".to_string(),
        settings: Some(serde_json::to_value(tcp_cfg)?),
        stream_settings: None,
        sniffing: None,
    });

    // Add sample HTTPS inbound with TLS (requires server.crt/server.key files)
    #[derive(serde::Serialize)]
    struct SampleHttpsCfg { tls: rust_core::config::TlsSettings }
    let https_cfg = SampleHttpsCfg { tls: rust_core::config::TlsSettings {
        server_name: None,
        allow_insecure: None,
        certificate_file: Some("server.crt".to_string()),
        key_file: Some("server.key".to_string()),
        certificates: None,
    } };
    config.inbounds.push(rust_core::config::InboundConfig {
        tag: Some("https-in".to_string()),
        listen: Some("0.0.0.0".to_string()),
        port: 8443,
        protocol: "https".to_string(),
        settings: Some(serde_json::to_value(https_cfg)?),
        stream_settings: None,
        sniffing: None,
    });

    // Add sample UDP port mapping inbound: listen 127.0.0.1:5353 -> 1.1.1.1:53
    #[derive(serde::Serialize)]
    struct SampleUdpCfg { address: String, port: u16 }
    let udp_cfg = SampleUdpCfg { address: "1.1.1.1".to_string(), port: 53 };
    config.inbounds.push(rust_core::config::InboundConfig {
        tag: Some("udp-map".to_string()),
        listen: Some("127.0.0.1".to_string()),
        port: 5353,
        protocol: "udp".to_string(),
        settings: Some(serde_json::to_value(udp_cfg)?),
        stream_settings: None,
        sniffing: None,
    });
    
    // Add sample outbound
    config.outbounds.push(rust_core::config::OutboundConfig {
        tag: Some("direct-out".to_string()),
        protocol: "direct".to_string(),
        settings: None,
        stream_settings: None,
        proxy_settings: None,
    });
    
    // Add sample Shadowsocks outbound
    let ss_config = shadowsocks::ShadowsocksConfig {
        address: Some("example.com".to_string()),
        port: 8388,
        method: "aes-256-gcm".to_string(),
        password: "your-password".to_string(),
        udp: Some(true),
        level: Some(0),
        email: None,
    };
    
    config.outbounds.push(rust_core::config::OutboundConfig {
        tag: Some("ss-out".to_string()),
        protocol: "shadowsocks".to_string(),
        settings: Some(serde_json::to_value(ss_config)?),
        stream_settings: None,
        proxy_settings: None,
    });
    
    // Add sample routing
    config.routing = Some(rust_core::config::RoutingConfig {
        domain_strategy: Some("IPIfNonMatch".to_string()),
        rules: vec![
            rust_core::config::RoutingRule {
                tag: Some("direct-rule".to_string()),
                rule_type: Some("field".to_string()),
                domain: Some(vec!["localhost".to_string(), "127.0.0.1".to_string()]),
                ip: None,
                port: None,
                source_port: None,
                network: None,
                source: None,
                user: None,
                inbound_tag: None,
                protocol: None,
                attrs: None,
                outbound_tag: "direct-out".to_string(),
                balancer_tag: None,
            },
            rust_core::config::RoutingRule {
                tag: Some("proxy-rule".to_string()),
                rule_type: Some("field".to_string()),
                domain: None,
                ip: None,
                port: None,
                source_port: None,
                network: None,
                source: None,
                user: None,
                inbound_tag: None,
                protocol: None,
                attrs: None,
                outbound_tag: "ss-out".to_string(),
                balancer_tag: None,
            },
        ],
        balancers: None,
    });
    
    config.to_file(output_path.to_str().unwrap())?;
    
    info!("Sample configuration generated successfully");
    Ok(())
}

async fn validate_config(config_path: PathBuf) -> CoreResult<()> {
    info!("Validating configuration file {:?}", config_path);
    
    let config = Config::from_file(config_path.to_str().unwrap())?;
    config.validate()?;
    
    info!("Configuration validation passed");
    Ok(())
}

fn show_version() {
    println!("Rust-Core {}", rust_core::version());
    println!("A high-performance proxy core written in Rust");
    println!("Inspired by Xray-core architecture");
}
