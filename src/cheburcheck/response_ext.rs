use futures::{Stream, TryStreamExt};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_stream::wrappers::LinesStream;
use tokio_util::io::StreamReader;

use crate::cheburcheck::error::Error;

pub trait ResponseExt {
    fn into_lines_stream(self) -> impl Stream<Item = Result<String, Error>>;
    // fn into_vec(self) -> impl Future<Output = Result<Vec<String>, Error>>;
}

impl ResponseExt for reqwest::Response {
    fn into_lines_stream(self) -> impl Stream<Item = Result<String, Error>> {
        let stream = self
            .bytes_stream() //
            .map_err(|e| std::io::Error::other(e));

        let reader = StreamReader::new(stream);
        let reader = BufReader::new(reader);

        LinesStream::new(reader.lines()).map_err(|e| {
            let is_reqwest = e
                .get_ref()
                .map(|inner| inner.is::<reqwest::Error>())
                .unwrap_or(false);

            if is_reqwest {
                let inner = e.into_inner().expect("Already checked via get_ref");
                let req_err = inner
                    .downcast::<reqwest::Error>()
                    .expect("Safe due to check");

                Error::Request(*req_err)
            } else {
                Error::Io(e)
            }
        })
    }

    // fn into_vec(self) -> impl Future<Output = Result<Vec<String>, Error>> {
    //     async move { self.into_lines_stream().try_collect().await }
    // }
}
