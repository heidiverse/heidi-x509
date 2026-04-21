pub mod x509;
pub use x509_parser;

#[derive(Clone, Copy, Debug)]
pub enum ParseError {
    FailedToParseX509,
}
pub fn extract_public_key<T: AsRef<[u8]>>(cert: T) -> Result<Vec<u8>, ParseError> {
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(cert.as_ref()) else {
        return Err(ParseError::FailedToParseX509);
    };
    Ok(cert.subject_pki.raw.to_vec())
}
