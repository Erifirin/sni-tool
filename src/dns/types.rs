use std::fmt;
use std::net::IpAddr;

use hickory_resolver::ResolveError;

pub struct DomainIpSet {
    domain: String,
    ipset: Vec<IpAddr>,
}

#[derive(Debug)]
pub struct DomainResolveError {
    domain: String,
    error: ResolveError,
}

impl DomainIpSet {
    pub fn new(domain: String, ips: Vec<IpAddr>) -> Self {
        Self { domain, ipset: ips }
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn ipset(&self) -> &[IpAddr] {
        &self.ipset
    }

    /// Decomposes `ResolvedDomain` into `(domain, ipset)`.
    pub fn into_parts(self) -> (String, Vec<IpAddr>) {
        (self.domain, self.ipset)
    }

    pub fn is_empty(&self) -> bool {
        self.ipset.is_empty()
    }
}

impl DomainResolveError {
    pub fn new(domain: String, error: ResolveError) -> Self {
        Self { domain, error }
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn error(&self) -> &ResolveError {
        &self.error
    }
}

impl From<DomainResolveError> for ResolveError {
    fn from(value: DomainResolveError) -> Self {
        value.error
    }
}

impl fmt::Display for DomainResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "failed to resolve domain '{}': {}",
            self.domain, self.error
        )
    }
}
