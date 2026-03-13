use std::{fs::File, path::Path};

use crate::parsers::{LinesParser, ParserError};

#[derive(Debug)]
pub struct AsnLine<'a> {
    pub asn: u32,
    pub domain: &'a str,
}

// pub fn parse_asn_file(
//     path: impl AsRef<Path>,
//     asns: impl IntoIterator<Item = u32>,
// ) -> Result<HashMap<u32, Vec<String>>, ParserError> {
//     let mut asn_domains: HashMap<u32, Vec<String>> = HashMap::new();
//     asn_domains.extend(asns.into_iter().map(|asn| (asn, Vec::<String>::new())));
//
//     let file = File::open(path)?;
//     let mut parser = LinesParser::new(file);
//
//     while let Some(item) = parser.read_line(parse_line)? {
//         if let Some(domains) = asn_domains.get_mut(&item.asn) {
//             domains.push(item.domain.to_string());
//         }
//     }
//
//     Ok(asn_domains)
// }

pub fn parse_asn_file<P, F>(path: P, mut action: F) -> Result<usize, ParserError>
where
    P: AsRef<Path>,
    F: FnMut(&AsnLine<'_>),
{
    let file = File::open(path)?;
    let mut parser = LinesParser::new(file);

    let mut count = 0;
    while let Some(item) = parser.read_line(parse_line)? {
        action(&item);
        count += 1;
    }

    Ok(count)
}

fn parse_line(line: &str) -> Result<AsnLine<'_>, ParserError> {
    let mut iter = line.split(';');

    let asn_s = iter
        .next()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to get asn from line '{}'.", line),
            )
        })?
        .trim();

    let domain = iter
        .next()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to get domain from line '{}'.", line),
            )
        })?
        .trim();

    let asn_s = asn_s.trim_start_matches(|c: char| !c.is_ascii_digit());
    let asn: u32 = asn_s.parse().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Failed to parse asn form string {}.", asn_s),
        )
    })?;

    Ok(AsnLine { asn, domain })
}

pub fn panic_on_error(e: ParserError) -> ! {
    match e {
        ParserError::Io(e) => panic!("Failed to read asn.csv\n{e}"),
        ParserError::Parser(e) => panic!("Failed to parse asn.csv\n{e}"),
    }
}
