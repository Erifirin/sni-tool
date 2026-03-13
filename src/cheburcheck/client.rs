use futures::Stream;

use super::error::Error;
use super::response_ext::ResponseExt;

#[derive(Debug)]
pub struct Client {
    https: reqwest::Client,
}

impl Client {
    pub fn new() -> Self {
        Self {
            https: reqwest::Client::new(),
        }
    }

    pub fn whitelisted_domains(&self) -> WhitelistedDomainsQuery<'_> {
        WhitelistedDomainsQuery { client: self }
    }

    pub(super) fn https(&self) -> &reqwest::Client {
        &self.https
    }
}

pub struct WhitelistedDomainsQuery<'a> {
    client: &'a Client,
}

impl<'a> WhitelistedDomainsQuery<'a> {
    pub async fn into_stream(self) -> Result<impl Stream<Item = Result<String, Error>>, Error> {
        self.client
            .https()
            .get("https://cheburcheck.ru/whitelist/domains.csv")
            .send()
            .await
            .map(ResponseExt::into_lines_stream)
            .map_err(Error::from)
    }
}
