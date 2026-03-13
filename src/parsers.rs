use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    io::{BufRead, BufReader, Read},
};

pub struct LinesParser<R> {
    reader: BufReader<R>,
    buffer: String,
}

#[derive(Debug)]
pub enum ParserError {
    Io(std::io::Error),
    Parser(String),
}

impl<R> LinesParser<R>
where
    R: Read,
{
    pub fn with_capacity(source: R, buffer_capacity: usize) -> Self {
        Self {
            reader: BufReader::new(source),
            buffer: String::with_capacity(buffer_capacity),
        }
    }

    pub fn new(source: R) -> Self {
        Self::with_capacity(source, 1024)
    }

    pub fn read_line<'a, F, D>(&'a mut self, parser: F) -> Result<Option<D>, ParserError>
    where
        F: Fn(&'a str) -> Result<D, ParserError>,
    {
        self.buffer.clear();
        if self.reader.read_line(&mut self.buffer)? > 0 {
            let str = self.buffer.trim_end();
            let item = parser(str)?;
            Ok(Some(item))
        } else {
            Ok(None)
        }
    }
}

impl From<std::io::Error> for ParserError {
    fn from(e: std::io::Error) -> Self {
        ParserError::Io(e)
    }
}

impl Display for ParserError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            ParserError::Io(e) => write!(f, "IO error: {}", e),
            ParserError::Parser(s) => write!(f, "parse error: {}", s),
        }
    }
}

// pub struct LazyParser<R, F, D> {
//     reader: BufReader<R>,
//     parser: F,
//     buffer: String,
//     _marker: PhantomData<D>,
// }
//
// impl<R: Read, F, D> LazyParser<R, F, D>
// where
//     F: Fn(&str) -> Result<D, ParserError>,
// {
//     pub fn new(inner: R, parser: F) -> Self {
//         Self {
//             reader: BufReader::new(inner),
//             parser,
//             buffer: String::with_capacity(1024),
//             _marker: PhantomData,
//         }
//     }
// }
//
// impl<R: Read, F, D> Iterator for LazyParser<R, F, D>
// where
//     F: Fn(&str) -> Result<D, ParserError>,
// {
//     type Item = Result<D, ParserError>;
//
//     fn next(&mut self) -> Option<Self::Item> {
//         self.buffer.clear();
//         match self.reader.read_line(&mut self.buffer) {
//             Ok(0) => None, // EOF
//             Ok(_) => {
//                 let trimmed = self.buffer.trim_end();
//                 let rs = (self.parser)(trimmed);
//                 Some(rs)
//             }
//             Err(e) => Some(Err(e.into())),
//         }
//     }
// }
