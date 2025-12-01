use clap::{Parser, Subcommand};
use rust_core::{
    config::Config,
    core::{Instance, new_with_defaults},
    protocols::{direct, shadowsocks},
    CoreResult,
};
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
    
    // Configure inbound handlers
    for inbound_config in &config.inbounds {
        let tag = inbound_config.tag.clone().unwrap_or_else(|| {
            format!("inbound-{}", inbound_config.port)
        });
        
        match inbound_config.protocol.as_str() {
            "direct" => {
                let handler = direct::create_direct_inbound(tag);
                instance.add_inbound_handler(handler).await?;
            }
            "shadowsocks" => {
                if let Some(settings) = &inbound_config.settings {
                    let ss_config: shadowsocks::ShadowsocksConfig = 
                        serde_json::from_value(settings.clone())?;
                    let handler = shadowsocks::create_shadowsocks_inbound(tag, ss_config);
                    instance.add_inbound_handler(handler).await?;
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
                instance.add_outbound_handler(handler).await?;
            }
            "shadowsocks" => {
                if let Some(settings) = &outbound_config.settings {
                    let ss_config: shadowsocks::ShadowsocksConfig = 
                        serde_json::from_value(settings.clone())?;
                    let handler = shadowsocks::create_shadowsocks_outbound(tag, ss_config);
                    instance.add_outbound_handler(handler).await?;
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
    
    // Start the instance
    instance.start().await?;
    
    info!("Rust-Core proxy server started successfully");
    
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
    
    // Add sample inbound
    config.inbounds.push(rust_core::config::InboundConfig {
        tag: Some("http-in".to_string()),
        listen: Some("127.0.0.1".to_string()),
        port: 8080,
        protocol: "direct".to_string(),
        settings: None,
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