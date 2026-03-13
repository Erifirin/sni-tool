use std::net::IpAddr;

use futures::Stream;
use hickory_resolver::{
    Resolver, TokioResolver, config::ResolverConfig, lookup_ip::LookupIp,
    name_server::TokioConnectionProvider,
};

use super::{
    DomainIpSet, DomainResolveError,
    query::{IteratorQuery, StreamQuery},
};

pub struct DnsResolver {
    resolver: TokioResolver,
}

impl DnsResolver {
    pub fn new() -> Self {
        let resolver = Resolver::builder_with_config(
            ResolverConfig::default(),
            TokioConnectionProvider::default(),
        )
        .build();

        Self { resolver }
    }

    pub fn resolve_ipset_from_iter<I>(&self, domains: I) -> IteratorQuery<'_, I>
    where
        I: IntoIterator,
        I::Item: Into<String>,
    {
        IteratorQuery::new(&self, domains)
    }

    pub fn resolve_ipset_from_stream<I>(&self, domains: I) -> StreamQuery<'_, I>
    where
        I: Stream + Unpin + Send,
        I::Item: Into<String>,
    {
        StreamQuery::new(&self, domains)
    }

    pub async fn resolve_ipset(
        &self,
        domain: impl Into<String>,
        limit: Option<usize>,
    ) -> Result<DomainIpSet, DomainResolveError> {
        let mut domain = domain.into();
        normalize_domain_name_mut(&mut domain);

        let lookup = self.resolver.lookup_ip(&domain).await;

        match lookup {
            Ok(lookup) => Ok(DomainIpSet::new(domain, lookup_to_ipset(lookup, limit))),
            Err(e) => Err(DomainResolveError::new(domain, e)),
        }
    }
}

fn normalize_domain_name_mut(domain: &mut String) {
    if !domain.ends_with('.') {
        domain.push('.');
    }
}

fn lookup_to_ipset(lookup: LookupIp, limit: Option<usize>) -> Vec<IpAddr> {
    match limit {
        Some(limit) if limit > 0 => {
            let mut ipset: Vec<IpAddr> = Vec::with_capacity(limit);
            for ip in lookup {
                ipset.push(ip);
            }
            ipset
        }
        _ => lookup.into_iter().collect(),
    }
}
