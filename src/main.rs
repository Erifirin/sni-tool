use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{BufWriter, Write},
    net::IpAddr,
    rc::Rc,
    str::FromStr,
};

use clap::{Args, Parser, Subcommand};
use tokio_stream::StreamExt;

mod cheburcheck;
mod cymru;
mod db;
mod dns;
mod hackertarget;
mod parsers;

/// CLI
#[derive(Parser, Debug)]
#[command(version, about = "A simple tool for finding whitelist-SNI (wSNI).", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

// db fetch
// db build
// lookup asn
// lookup wsni
// ls wsni --asn
#[derive(Subcommand, Debug)]
enum Commands {
    /// Local database management commands.
    #[command(arg_required_else_help = true)]
    Db(DbArgs),

    /// Lookup commands: ip, asn, whitelisted sni, etc
    #[command(arg_required_else_help = true)]
    Lookup(LookupArgs),

    /// Commands allows to list data from local database (if exists).
    #[command(arg_required_else_help = true)]
    Ls(ListArgs),
}

#[derive(Args, Debug)]
struct LookupArgs {
    #[command(subcommand)]
    command: LookupCommand,
}

#[derive(Debug, Subcommand)]
enum LookupCommand {
    /// Resolve ip address of specified domain.
    #[command(arg_required_else_help = true)]
    IP {
        /// domain to resolve.
        domain: String,

        /// Limit on the number of output lines
        #[arg(short, long)]
        limit: Option<usize>,
    },

    /// Look up ASN for specified host or ip address.
    #[command(arg_required_else_help = true)]
    ASN {
        /// Target host or ip
        target: String,

        /// Limit on the number of output lines
        #[arg(short, long)]
        limit: Option<usize>,
    },

    /// Look up whitelisted SNI for specified host or ip address.
    WSNI {
        /// Target host or ip
        target: String,

        /// Limit on the number of output lines
        #[arg(short, long)]
        limit: Option<usize>,
    },
}

#[derive(Args, Debug)]
struct ListArgs {
    #[command(subcommand)]
    command: ListCommand,
}

#[derive(Debug, Subcommand)]
enum ListCommand {
    /// List whitelisted SNIs from local database.
    WSNI {
        /// Filter by specified ASN.
        #[arg(short, long)]
        asn: Option<u32>,

        /// Limit on the number of output lines
        #[arg(short, long)]
        limit: Option<usize>,
    },
}

#[derive(Args, Debug)]
struct DbArgs {
    #[command(subcommand)]
    command: DbCommand,
}

#[derive(Debug, Subcommand)]
enum DbCommand {
    /// Build (or rebuild) local database.
    Build,

    /// Fetch database from public source.
    Fetch,
}

//-----------------------------------------------------------------------------
// Main
//-----------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Db(args) => match args.command {
            DbCommand::Build => db_build().await,
            DbCommand::Fetch => todo!(),
        },
        Commands::Lookup(args) => match args.command {
            LookupCommand::IP { domain, limit } => lookup_ip(domain, limit).await,
            LookupCommand::ASN { target, limit } => lookup_asn(target, limit).await,
            LookupCommand::WSNI { target, limit } => lookup_wsni(target, limit).await,
        },
        Commands::Ls(args) => match args.command {
            ListCommand::WSNI { asn, limit } => ls_wsni(asn, limit),
        },
    }

    Ok(())
}

//-----------------------------------------------------------------------------
// Common
//-----------------------------------------------------------------------------

async fn resolve_target_ips(target: &str, limit: Option<usize>) -> Vec<IpAddr> {
    if target.trim().is_empty() {
        panic!("No target to lookup.");
    }

    if let Ok(ip) = IpAddr::from_str(target) {
        return vec![ip];
    }

    resolve_ip(target, limit).await
}

async fn resolve_ip(domain: &str, limit: Option<usize>) -> Vec<IpAddr> {
    let dns = dns::create_resolver();
    let mut ips: Vec<IpAddr> = match limit {
        Some(limit) => Vec::with_capacity(limit),
        None => Vec::new(),
    };

    dns::resolve_ips_to_vec(&dns, domain, &mut ips, limit)
        .await
        .unwrap_or_else(|e| panic!("Failed to resolve ip for domain '{domain}'.\n{e}"));

    if ips.is_empty() {
        panic!("No resolved ips for target '{domain}'.");
    }

    ips
}

async fn resolve_asns(ips: &[IpAddr]) -> HashSet<u32> {
    let mut asns: HashSet<u32> = HashSet::with_capacity(ips.len());

    println!(
        "{:15} | {:18} | {:10} | {}",
        "IP", "CIDR", "ASN", "ASN Name"
    );
    for ip in ips {
        match hackertarget::resolve_ip(*ip).await {
            Ok(info) => {
                asns.insert(info.asn());
                println!(
                    "{:15} | {:18} | {:<10} | {}",
                    info.ip(),
                    info.cidr(),
                    info.asn(),
                    info.asn_name()
                );
            }
            Err(e) => {
                eprintln!("{:15} | {}", &ip, e);
            }
        }
    }

    asns
}

//-----------------------------------------------------------------------------
// Lookup IP
//-----------------------------------------------------------------------------

async fn lookup_ip(domain: String, limit: Option<usize>) {
    resolve_ip(&domain, limit)
        .await
        .into_iter()
        .for_each(|ip| println!("  {}", ip));
}

//-----------------------------------------------------------------------------
// Lookup ASN
//-----------------------------------------------------------------------------

async fn lookup_asn(target: String, limit: Option<usize>) {
    let ips = resolve_target_ips(&target, limit).await;
    resolve_asns(&ips).await;
}

//-----------------------------------------------------------------------------
// Lookup SNI
//-----------------------------------------------------------------------------

async fn lookup_wsni(target: String, limit: Option<usize>) {
    let ips = resolve_target_ips(&target, limit).await;
    let asns = resolve_asns(&ips).await;

    println!();
    ls_wsni_batch(asns, limit);
}

//-----------------------------------------------------------------------------
// Lint SNI
//-----------------------------------------------------------------------------

fn ls_wsni(asn: Option<u32>, limit: Option<usize>) {
    let mut domains: Vec<String> = Vec::new();

    // TODO: при наличии лимита нет смысла читать файл до конца
    println!("Collecting whitelisted SNIs...");
    db::parse_asn_file("asn.csv", |item| {
        if asn == None || asn == Some(item.asn) {
            domains.push(item.domain.to_string());
        }
    })
    .unwrap();

    print_sni_list(&mut domains, limit);
}

fn ls_wsni_batch(asns: impl IntoIterator<Item = u32>, limit: Option<usize>) {
    println!("Collecting whitelisted SNIs...");

    let mut asn_domains: HashMap<u32, Vec<String>> =
        asns.into_iter().map(|asn| (asn, Vec::new())).collect();

    db::parse_asn_file("asn.csv", |item| {
        let domain = item.domain.to_string();
        if let Some(domains) = asn_domains.get_mut(&item.asn) {
            domains.push(domain);
        }
    })
    .unwrap();

    for (asn, mut domains) in asn_domains {
        println!("ASN {}:", asn);
        print_sni_list(&mut domains, limit);
    }
}

fn print_sni_list(domains: &mut Vec<String>, limit: Option<usize>) {
    if domains.is_empty() {
        println!("  No domains found.\n");
        return;
    }

    domains.sort_unstable();
    let limit = limit.filter(|x| *x > 0);
    if let Some(limit) = limit {
        domains.iter().take(limit).for_each(print);
    } else {
        domains.iter().for_each(print);
    }
    println!();

    fn print(domain: &String) {
        println!("  {domain}");
    }
}

//-----------------------------------------------------------------------------
// DB build
//-----------------------------------------------------------------------------

async fn db_build() {
    // request whitelisted domains
    println!("Request whitelisted domains...");
    let domains_stream = cheburcheck::request_domains()
        .await
        .unwrap()
        .into_lines_stream();

    // request ips
    println!("Resolve IPs...");
    let dns = dns::create_resolver();
    let mut resolved_domains_stream = dns::resolve_ips_stream(&dns, domains_stream);

    // make a map of pairs ip-domain
    let mut total_domains = 0u32;
    let mut resolved_domains = 0u32;
    let mut ip_domain: HashMap<IpAddr, Rc<String>> = HashMap::with_capacity(1000);
    while let Some(rs) = resolved_domains_stream.next().await {
        total_domains += 1;
        match rs {
            Ok(info) => {
                let (domain, ips) = info.into_parts();
                let domain = Rc::new(domain);
                for ip in ips {
                    ip_domain.insert(ip, Rc::clone(&domain));
                }
                resolved_domains += 1;
                // print!("\r  Resolved ip for {}", domain);
            }
            Err(e) => eprintln!("  Failed to resolve IP for {} {}", e.domain(), e.error()),
        }
    }

    // resolve asns
    println!("Resolve ASNs...");
    let ip_info = cymru::resolve_asn_batch(ip_domain.keys()).await.unwrap();

    // data processing
    println!("Data processing...");
    let asn_domain: HashSet<_> = ip_info
        .into_iter()
        .filter_map(|(ip, info)| {
            let Some(domain) = ip_domain.remove(&ip) else {
                println!("  Failed to get domain for ip {ip}");
                return None;
            };

            Some((info.asn(), domain))
        })
        .collect();

    // output
    let resolved_asns = asn_domain.len();
    let mut records = Vec::with_capacity(asn_domain.len());
    records.extend(asn_domain);
    records.sort_unstable();

    println!("Writing asn.csv...");
    write_asn_file(&records).unwrap();

    println!();
    println!("Done!");
    println!();
    println!("Summary:");
    println!("  Whitelisted domains: {}", total_domains);
    println!("  Resolved domains: {}", resolved_domains);
    println!("  Resolved ASNs: {}", resolved_asns);

    if !ip_domain.is_empty() {
        println!();
        println!("Unable to resolve ASN for the following domains:");
        for (_, domain) in ip_domain {
            println!("  {domain}");
        }
    }
}

fn write_asn_file(asn_domain: &[(u32, Rc<String>)]) -> Result<(), std::io::Error> {
    let file = File::create("asn.csv")?;
    let mut writer = BufWriter::new(file);
    for (asn, domain) in asn_domain {
        writeln!(writer, "{asn};{domain}")?;
    }
    println!();

    Ok(())
}

// fn get_domains_list(path: impl AsRef<Path>) -> std::io::Result<Vec<String>> {
//     let file = File::open(path)?;
//     let mut reader = BufReader::new(file);
//     let mut buffer = String::with_capacity(256);
//     let mut rs: HashSet<String> = HashSet::with_capacity(2000);
//     while reader.read_line(&mut buffer)? > 0 {
//         let domain = buffer.trim();
//         if domain.is_empty() {
//             continue;
//         }
//         let domain = if domain.ends_with('.') {
//             domain.to_string()
//         } else {
//             format!("{domain}.")
//         };
//         rs.insert(domain);
//         buffer.clear();
//     }
//
//     Ok(rs.into_iter().collect())
// }

// async fn get_domain_info<T: AsRef<str> + Display>(
//     dns: &TokioResolver,
//     domains: &[T],
// ) -> Result<(), Box<dyn std::error::Error>> {
//     // resolve ips
//     let capacity = domains.len();
//     // let mut ipset: HashMap<IpAddr, &str> = HashMap::with_capacity(capacity);
//
//     // let mut ips_buf = [IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)); 5];
//     // for domain in domains {
//     //     let Ok(ips) = resolve_ips(dns, domain.as_ref(), &mut ips_buf).await else {
//     //         println!("Failed to resolve ip for {domain}");
//     //         continue;
//     //     };
//     //
//     //     for ip in ips {
//     //         ipset.insert(*ip, domain.as_ref());
//     //     }
//     // }
//
//     let mut ipset: HashMap<IpAddr, Rc<String>> = HashMap::with_capacity(capacity);
//     let iter = domains.iter().map(|x| x.as_ref());
//     let mut ips_stream = dns::resolve_ips_batch_stream(&dns, iter).await;
//     while let Some(rec) = ips_stream.next().await {
//         if let Ok(ips) = rec.ip {
//             let domain = Rc::new(rec.domain);
//             for ip in ips {
//                 ipset.insert(ip, Rc::clone(&domain));
//             }
//         }
//     }
//
//     // resolve asns
//     let ips = ipset.keys();
//     let info = cymru::resolve_asn_batch(ips).await?;
//
//     // prepare report
//     let asns: HashSet<_> = info
//         .iter()
//         .filter_map(|(ip, info)| {
//             let Some(domain) = ipset.remove(ip) else {
//                 println!("Failed to get domain for ip {ip}");
//                 return None;
//             };
//
//             Some((info.get_asn(), domain))
//         })
//         .collect();
//
//     let mut report: Vec<_> = asns.into_iter().collect();
//     report.sort_unstable();
//
//     // output
//     let file = File::create("asn.csv")?;
//     let mut writer = BufWriter::new(file);
//     let mut buffer = String::with_capacity(256);
//     for (asn, domain) in report {
//         buffer.clear();
//         writeln!(&mut buffer, "{asn};{domain}")?;
//         std::io::Write::write_all(&mut writer, buffer.as_bytes())?;
//         print!("{buffer}");
//     }
//
//     for (_, domain) in ipset {
//         buffer.clear();
//         writeln!(&mut buffer, "N/A;{domain}")?;
//         std::io::Write::write_all(&mut writer, buffer.as_bytes())?;
//         println!("{buffer}");
//     }
//
//     Ok(())
// }

//
// Tests
//

// #[cfg(test)]
// mod tests {
//     use super::*;
//
//     #[test]
//     fn dev_print_asns() {
//         let asns = [13335u32, 16509];
//         find_white_sni(asns)
//     }
// }
