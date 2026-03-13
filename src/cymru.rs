use std::{collections::HashMap, fmt::Write, net::IpAddr};

use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter},
    net::TcpStream,
};

const CYMRU_WHOIS_URI: &str = "whois.cymru.com:43";

// pub struct AsnResolver {
//     // resolve_asn
//     // resolve_asn_from_iter -> AsnIterResolver
//     // resolve_asn_from_stream -> AsnStreamResolver
// }
//
// struct AsnIter {
//     // into_iter()
//     // into_stream()
// }
//
// pub trait AsnIterResolver {
//     fn into_iter(self) -> impl Iterator<Item = IpInfo>;
//     fn into_stream(self) ->
// }

#[derive(Debug)]
pub struct IpInfo {
    ip: IpAddr,
    asn: u32,
    asn_name: Option<String>,
}

impl IpInfo {
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            asn: 0,
            asn_name: None,
        }
    }

    pub fn asn(&self) -> u32 {
        return self.asn;
    }
}

pub enum ResolvingError {}

pub async fn resolve_asn_batch(
    ips: impl Iterator<Item = &IpAddr>,
) -> Result<HashMap<IpAddr, IpInfo>, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(CYMRU_WHOIS_URI).await?;
    let (reader, writer) = stream.split();
    let mut buffer = String::with_capacity(1024);

    // write header
    let mut writer = BufWriter::new(writer);
    write_line(&mut buffer, &mut writer, "begin").await?;
    // write_line(&mut buf, &mut wbuf, "verbose").await?;

    // while ip list
    let mut count = 0;
    for ip in ips {
        buffer.clear();
        write!(&mut buffer, "{}\n", ip)?;
        writer.write_all(buffer.as_bytes()).await?;
        count += 1;
    }

    write_line(&mut buffer, &mut writer, "end").await?;
    writer.flush().await?;

    // read response
    let mut dataset = HashMap::<IpAddr, IpInfo>::with_capacity(count);
    let mut reader = BufReader::new(reader);
    while let Some(ip) = read_line(&mut buffer, &mut reader).await? {
        if let Ok(info) = parse_line(ip) {
            dataset.insert(info.ip, info);
        }
    }

    Ok(dataset)
}

async fn write_line<W>(
    buffer: &mut String,
    writer: &mut BufWriter<W>,
    line: &str,
) -> tokio::io::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    buffer.clear();
    buffer.push_str(line);
    buffer.push('\n');
    writer.write_all(buffer.as_bytes()).await?;

    Ok(())
}

async fn read_line<'a, R>(
    buffer: &'a mut String,
    reader: &mut BufReader<R>,
) -> tokio::io::Result<Option<&'a str>>
where
    R: AsyncReadExt + Unpin,
{
    loop {
        buffer.clear();

        let len = reader.read_line(buffer).await?;
        if len == 0 {
            return Ok(None);
        }

        if buffer.trim().is_empty() {
            continue;
        }

        return Ok(Some(buffer));
    }
}

// fn parse_file() -> Result<HashMap<IpAddr, IpInfo>, std::io::Error> {
//     let file = File::open("cymru.out")?;
//     let mut reader = BufReader::new(file);
//     let mut dataset = HashMap::<IpAddr, IpInfo>::with_capacity(1024);
//
//     let mut buffer: String = String::with_capacity(512);
//     while reader.read_line(&mut buffer)? > 0 {
//         if let Ok(info) = parse_line(&buffer) {
//             dataset.insert(info.ip, info);
//         }
//         buffer.clear();
//     }
//
//     Ok(dataset)
// }

fn parse_line(line: &str) -> Result<IpInfo, &str> {
    let mut iter = line.split('|');

    let s_asn = iter.next().ok_or("Failed to get asn.")?.trim();
    let s_ip = iter.next().ok_or("Failed to get ip.")?.trim();
    let s_asn_name = iter.next().map(|s| s.trim());

    let ip: IpAddr = s_ip.parse().map_err(|_| "Failed to parse ip.")?;
    let asn: u32 = s_asn.parse().map_err(|_| "Failed to parse asn")?;
    let name = s_asn_name.map(|s| s.to_string());

    let mut info = IpInfo::new(ip);
    info.asn = asn;
    info.asn_name = name;

    Ok(info)
}

// use tokio::fs::File;
// use tokio::io;
//
// async fn transfer(mut writer: tokio::net::tcp::WriteHalf<'_>) -> io::Result<()> {
//     let mut file = File::open("large_file.txt").await?;
//     // Копирует данные напрямую, используя фиксированный буфер в 8КБ
//     io::copy(&mut file, &mut writer).await?;
//     Ok(())
// }
//
//
//use tokio::fs::File;
// use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
//
// async fn transfer_by_line(mut writer: tokio::net::tcp::WriteHalf<'_>) -> io::Result<()> {
//     let file = File::open("large_file.txt").await?;
//     let reader = BufReader::new(file);
//     let mut lines = reader.lines();
//
//     while let Some(line) = lines.next_line().await? {
//         // Записываем строку и добавляем перевод строки
//         writer.write_all(line.as_bytes()).await?;
//         writer.write_all(b"\n").await?;
//     }
//
//     writer.flush().await?; // Важно вызвать flush для завершения записи
//     Ok(())
// }
//
