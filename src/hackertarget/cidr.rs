use std::{fmt, net::IpAddr, str::FromStr};

use serde::{
    Deserializer,
    de::{self, Visitor},
};

#[derive(Debug)]
pub struct Cidr {
    ip: IpAddr,
    mask: u8,
}

#[allow(dead_code)]
struct CidrVisitor;

impl Cidr {
    pub fn ip(&self) -> &IpAddr {
        &self.ip
    }

    pub fn mask(&self) -> u8 {
        self.mask
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let str = format!("{}/{}", self.ip, self.mask);
        f.pad(&str)
    }
}

impl<'de> de::Deserialize<'de> for Cidr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(CidrVisitor)
    }
}

impl<'de> Visitor<'de> for CidrVisitor {
    type Value = Cidr;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string in CIDR notation (e.g. 192.168.1.0/24)")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let mut parts = v.splitn(2, '/');

        let ip_str = parts
            .next()
            .ok_or_else(|| de::Error::invalid_value(de::Unexpected::Str(v), &self))?;
        let mask_str = parts
            .next()
            .ok_or_else(|| de::Error::invalid_value(de::Unexpected::Str(v), &self))?;

        let ip = IpAddr::from_str(ip_str).map_err(|_| {
            de::Error::invalid_value(de::Unexpected::Str(ip_str), &"a valid ip address")
        })?;
        let mask = mask_str.parse::<u8>().map_err(|_| {
            de::Error::invalid_value(de::Unexpected::Str(mask_str), &"a valid ip mask")
        })?;

        if (ip.is_ipv4() && mask > 32) || (ip.is_ipv6() && mask > 128) {
            return Err(de::Error::invalid_value(
                de::Unexpected::Unsigned(mask as u64),
                &"a valid mask length (0-32 for IPv4, 0-128 for IPv6)",
            ));
        }

        Ok(Cidr { ip, mask })
    }
}
