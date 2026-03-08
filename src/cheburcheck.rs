use futures::TryStreamExt;
use reqwest::Error;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, BufReader, Lines};
use tokio_stream::wrappers::LinesStream;
use tokio_util::io::StreamReader;

pub struct Domains<R>
where
    R: AsyncBufRead + Unpin,
{
    inner: R,
}

impl<R> Domains<R>
where
    R: AsyncBufRead + Unpin,
{
    fn new(inner: R) -> Self {
        Self { inner }
    }

    pub fn into_lines(self) -> Lines<R> {
        self.inner.lines()
    }

    pub fn into_lines_stream(self) -> LinesStream<R> {
        LinesStream::new(self.inner.lines())
    }
}

pub async fn request_domains() -> Result<Domains<impl AsyncBufRead>, Error> {
    let response = reqwest::get("https://cheburcheck.ru/whitelist/domains.csv").await?;

    let stream = response
        .bytes_stream()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e));

    let stream_reader = StreamReader::new(stream);
    let buf_reader = BufReader::new(stream_reader);
    let ds = Domains::new(buf_reader);
    Ok(ds)
    // let mut buffer: String = String::with_capacity(256);
    // while reader.read_line(&mut buffer).await? > 0 {
    //     if !buffer.is_empty() &&
    //     buffer.clear();
    // }
}
