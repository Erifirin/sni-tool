mod cidr;

use std::net::IpAddr;

use reqwest::Error;
use serde::Deserialize;
use serde_with::{DisplayFromStr, serde_as};

pub use self::cidr::Cidr;

#[serde_as]
#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub struct IpResolveResult {
    ip: IpAddr,
    #[serde_as(as = "DisplayFromStr")]
    asn: u32,
    asn_name: String,
    asn_range: Cidr,
}

impl IpResolveResult {
    pub fn ip(&self) -> &IpAddr {
        &self.ip
    }

    pub fn cidr(&self) -> &Cidr {
        &self.asn_range
    }

    pub fn asn(&self) -> u32 {
        self.asn
    }

    pub fn asn_name(&self) -> &str {
        &self.asn_name
    }
}

/*
* curl "https://api.hackertarget.com/aslookup/?q=8.8.8.8&output=json
* {
*   "asn": "15169",
*   "asn_name": "GOOGLE, US",
*   "asn_range": "8.8.8.0/24",
*   "ip": "8.8.8.8"
* }
*/
pub async fn resolve_ip(addr: IpAddr) -> Result<IpResolveResult, Error> {
    let url = format!("https://api.hackertarget.com/aslookup/?q={addr}&output=json");
    // let url = Url::parse(url.as_ref());
    reqwest::get(url).await?.json::<IpResolveResult>().await
}
