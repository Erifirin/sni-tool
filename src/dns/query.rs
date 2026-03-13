use futures::{Stream, StreamExt};

use super::resolver::DnsResolver;
use super::types::{DomainIpSet, DomainResolveError};

const DEFAULT_CONCURRENT_TASKS: usize = 50;

pub struct IteratorQuery<'a, I>
where
    I: IntoIterator,
    I::Item: Into<String>,
{
    resolver: &'a DnsResolver,
    source: I,
    concurrent_tasks: usize,
}

pub struct StreamQuery<'a, I>
where
    I: Stream + Unpin + Send,
    I::Item: Into<String>,
{
    resolver: &'a DnsResolver,
    source: I,
    concurrent_tasks: usize,
}

impl<'a, I> IteratorQuery<'a, I>
where
    I: IntoIterator,
    I::Item: Into<String>,
{
    pub(super) fn new(resolver: &'a DnsResolver, source: I) -> Self {
        Self {
            resolver,
            source,
            concurrent_tasks: DEFAULT_CONCURRENT_TASKS,
        }
    }

    pub fn set_concurrent_tasks(&mut self, mut num: usize) -> &Self {
        if num == 0 {
            num = DEFAULT_CONCURRENT_TASKS;
        }

        self.concurrent_tasks = num;
        self
    }

    pub fn into_stream(
        self,
    ) -> impl Stream<Item = Result<DomainIpSet, DomainResolveError>> + Unpin {
        let resolver = self.resolver;

        tokio_stream::iter(self.source)
            .map(move |domain| resolver.resolve_ipset(domain.into(), None))
            .buffer_unordered(self.concurrent_tasks)
    }
}

impl<'a, I> StreamQuery<'a, I>
where
    I: Stream + Unpin + Send,
    I::Item: Into<String>,
{
    pub(super) fn new(resolver: &'a DnsResolver, source: I) -> Self {
        Self {
            resolver,
            source,
            concurrent_tasks: DEFAULT_CONCURRENT_TASKS,
        }
    }

    pub fn into_stream(
        self,
    ) -> impl Stream<Item = Result<DomainIpSet, DomainResolveError>> + Unpin {
        let resolver = self.resolver;

        self.source
            // .map_err(|e| {
            //     eprintln!("Error reading line: {}", e);
            // })
            // .filter_map(|res| async { res.ok() })
            .map(move |domain| resolver.resolve_ipset(domain.into(), None))
            .buffer_unordered(self.concurrent_tasks)
    }
}
