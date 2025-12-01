use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rust_core::{
    features::routing::{Context, DefaultRouter, DomainRule, IpRule},
    CoreResult,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

async fn create_test_router() -> DefaultRouter {
    let router = DefaultRouter::new();
    
    // Add domain rules
    let domain_rule = Box::new(DomainRule::new(
        vec![
            "example.com".to_string(),
            "test.org".to_string(),
            "github.com".to_string(),
            "google.com".to_string(),
            "cloudflare.com".to_string(),
        ],
        "proxy".to_string(),
    ));
    router.add_rule(domain_rule, true).await.unwrap();
    
    // Add IP rules
    let ip_cidrs = vec![
        "192.168.0.0/16".parse().unwrap(),
        "10.0.0.0/8".parse().unwrap(),
        "172.16.0.0/12".parse().unwrap(),
    ];
    let ip_rule = Box::new(IpRule::new(ip_cidrs, "direct".to_string()));
    router.add_rule(ip_rule, true).await.unwrap();
    
    router
}

fn create_test_contexts() -> Vec<Context> {
    vec![
        // Domain-based contexts
        Context::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 80)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 80)),
        ).with_domain("example.com".to_string()),
        
        Context::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 80)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 80)),
        ).with_domain("github.com".to_string()),
        
        Context::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 80)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 80)),
        ).with_domain("unknown.com".to_string()),
        
        // IP-based contexts
        Context::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 80)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 80)),
        ),
        
        Context::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 80)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 80)),
        ),
        
        Context::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 80)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 80)),
        ),
    ]
}

fn bench_routing_single(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let router = rt.block_on(create_test_router());
    let contexts = create_test_contexts();
    
    c.bench_function("routing_single", |b| {
        b.to_async(&rt).iter(|| async {
            for context in &contexts {
                let route = router.pick_route(black_box(context)).await.unwrap();
                black_box(route);
            }
        });
    });
}

fn bench_routing_parallel(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let router = rt.block_on(create_test_router());
    let contexts = create_test_contexts();
    
    c.bench_function("routing_parallel", |b| {
        b.to_async(&rt).iter(|| async {
            let futures: Vec<_> = contexts.iter().map(|context| {
                router.pick_route(black_box(context))
            }).collect();
            
            let routes = futures::future::join_all(futures).await;
            for route in routes {
                black_box(route.unwrap());
            }
        });
    });
}

fn bench_domain_matching(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    
    let rule = DomainRule::new(
        vec![
            "example.com".to_string(),
            "test.org".to_string(),
            "github.com".to_string(),
            "google.com".to_string(),
            "cloudflare.com".to_string(),
        ],
        "proxy".to_string(),
    );
    
    let context = Context::new(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 80)),
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 80)),
    ).with_domain("example.com".to_string());
    
    c.bench_function("domain_matching", |b| {
        b.to_async(&rt).iter(|| async {
            let matches = rule.matches(black_box(&context)).await;
            black_box(matches);
        });
    });
}

fn bench_ip_matching(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    
    let ip_cidrs = vec![
        "192.168.0.0/16".parse().unwrap(),
        "10.0.0.0/8".parse().unwrap(),
        "172.16.0.0/12".parse().unwrap(),
        "169.254.0.0/16".parse().unwrap(),
        "224.0.0.0/4".parse().unwrap(),
    ];
    let rule = IpRule::new(ip_cidrs, "direct".to_string());
    
    let context = Context::new(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 80)),
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 80)),
    );
    
    c.bench_function("ip_matching", |b| {
        b.to_async(&rt).iter(|| async {
            let matches = rule.matches(black_box(&context)).await;
            black_box(matches);
        });
    });
}

fn bench_router_creation(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    
    c.bench_function("router_creation", |b| {
        b.to_async(&rt).iter(|| async {
            let router = black_box(create_test_router().await);
            black_box(router);
        });
    });
}

criterion_group!(
    benches,
    bench_routing_single,
    bench_routing_parallel,
    bench_domain_matching,
    bench_ip_matching,
    bench_router_creation
);
criterion_main!(benches);