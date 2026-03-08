use std::{borrow::Cow, net::IpAddr};

use futures::{Stream, StreamExt, TryStreamExt, stream::BoxStream};
use hickory_resolver::{
    ResolveError, Resolver, TokioResolver, config::ResolverConfig,
    name_server::TokioConnectionProvider,
};

pub fn create_resolver() -> TokioResolver {
    Resolver::builder_with_config(
        ResolverConfig::default(),
        TokioConnectionProvider::default(),
    )
    .build()
}

pub async fn resolve_ips_to_vec(
    resolver: &TokioResolver,
    domain: &str,
    buffer: &mut Vec<IpAddr>,
    limit: Option<usize>,
) -> Result<usize, ResolveError> {
    let domain = normalize_domain_name(domain);
    let records = resolver.lookup_ip(domain.as_ref()).await?;

    let len0 = buffer.len();
    if let Some(limit) = limit {
        buffer.extend(records.into_iter().take(limit));
    } else {
        buffer.extend(records.into_iter());
    }
    Ok(buffer.len() - len0)
}

pub async fn resolve_ips<'a>(
    resolver: &TokioResolver,
    domain: &str,
    buffer: &'a mut [IpAddr],
) -> Result<&'a [IpAddr], ResolveError> {
    let domain = normalize_domain_name(domain);
    let records = resolver.lookup_ip(domain.as_ref()).await?;
    let mut count = 0;
    for (dst, src) in buffer.iter_mut().zip(records.iter()) {
        *dst = src;
        count += 1;
    }

    Ok(&buffer[0..count])
}

fn normalize_domain_name(domain: &str) -> Cow<'_, str> {
    if domain.ends_with('.') {
        Cow::Borrowed(domain)
    } else {
        Cow::Owned(format!("{domain}."))
    }
}

fn normalize_domain_name_mut(domain: &mut String) {
    if !domain.ends_with('.') {
        domain.push('.');
    }
}

pub struct IpResolveResult {
    pub domain: String,
    pub ips: Result<Vec<IpAddr>, ResolveError>,
}

pub async fn resolve_ips_batch(
    resolver: &TokioResolver,
    domains: impl Iterator<Item = &str>,
) -> Result<Vec<IpResolveResult>, ResolveError> {
    let mut rs: Vec<IpResolveResult> = Vec::with_capacity(1024);
    for domain in domains {
        let norm_domain = normalize_domain_name(domain);
        let lookup = resolver.lookup_ip(norm_domain.as_ref()).await;
        let rec = match lookup {
            Ok(ip) => IpResolveResult {
                domain: domain.to_string(),
                ips: Ok(ip.into_iter().collect()),
            },
            Err(e) => IpResolveResult {
                domain: domain.to_string(),
                ips: Err(e),
            },
        };
        rs.push(rec);
    }

    Ok(rs)
}

// async fn foo(resolver: &TokioResolver, domain: &str) -> IpResolveResult {
//     let lookup = resolver.lookup_ip(domain).await;
//     match lookup {
//         Ok(ip) => IpResolveResult {
//             domain: domain.to_string(),
//             ip: Ok(ip.into_iter().collect()),
//         },
//         Err(e) => IpResolveResult {
//             domain: domain.to_string(),
//             ip: Err(e),
//         },
//     }
// }

pub async fn resolve_ips_batch_stream<I>(
    resolver: &TokioResolver,
    domains: I,
) -> impl Stream<Item = IpResolveResult>
where
    I: Iterator,
    I::Item: Into<String>,
{
    tokio_stream::iter(domains)
        .map(move |domain| resolve_domain_ips(resolver, domain.into()))
        .buffer_unordered(50)
}

pub fn resolve_ips_stream<'a, S>(
    resolver: &'a TokioResolver,
    domains: S,
) -> BoxStream<'a, IpResolveResult>
where
    S: Stream<Item = Result<String, std::io::Error>> + Send + 'a,
{
    let rs = domains
        .map_err(|e| {
            eprintln!("Error reading line: {}", e);
        })
        .filter_map(|res| async { res.ok() })
        .map(|domain| resolve_domain_ips(resolver, domain))
        .buffer_unordered(50);

    Box::pin(rs)
}

async fn resolve_domain_ips(resolver: &TokioResolver, mut domain: String) -> IpResolveResult {
    normalize_domain_name_mut(&mut domain);
    // print!("\rResolve ip for {domain}");
    let lookup = resolver.lookup_ip(&domain).await;
    let ip = match lookup {
        Ok(ips) => Ok(ips.into_iter().collect::<Vec<_>>()),
        Err(e) => {
            // eprintln!("\rFailed to resolve IP for {domain} {e}");
            Err(e)
        }
    };

    IpResolveResult { domain, ips: ip }
}

// pub async fn resolve_ips_batch_parallel<I>(
//     resolver: &TokioResolver,
//     domains: I,
// ) -> Vec<IpResolveResult>
// where
//     I: Iterator,
//     I::Item: Into<String>,
// {
//     tokio_stream::iter(domains)
//         .map(|domain| {
//             let mut domain = domain.into();
//             normalize_domain_name2(&mut domain);
//             async move {
//                 let lookup = resolver.lookup_ip(&domain).await;
//                 match lookup {
//                     Ok(_) => println!("IP Resolved for {domain}"),
//                     Err(_) => println!("Failed to resolve IP for {domain}"),
//                 }
//
//                 IpResolveResult {
//                     domain,
//                     ip: lookup.map(|ip| ip.into_iter().collect()),
//                 }
//             }
//         })
//         .buffer_unordered(50)
//         .collect::<Vec<_>>()
//         .await
// }
