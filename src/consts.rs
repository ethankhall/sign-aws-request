use hyper::header::{self, HeaderName};
use lazy_static::lazy_static;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC};
use regex::Regex;

// http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
//
// Do not URI-encode any of the unreserved characters that RFC 3986 defines:
// A-Z, a-z, 0-9, hyphen ( - ), underscore ( _ ), period ( . ), and tilde ( ~ ).
//
// Percent-encode all other characters with %XY, where X and Y are hexadecimal
// characters (0-9 and uppercase A-F). For example, the space character must be
// encoded as %20 (not using '+', as some encoding schemes do) and extended UTF-8
// characters must be in the form %XY%ZA%BC
/// This constant is used to maintain the strict URI encoding standard as proposed by RFC 3986
pub const STRICT_ENCODE_SET: AsciiSet = NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// This struct is used to maintain the URI path encoding
pub const STRICT_PATH_ENCODE_SET: AsciiSet = STRICT_ENCODE_SET.remove(b'/');

pub const ISO_8601_DATETIME: &'static str = "%Y%m%dT%H%M%SZ";
pub const ISO_8601_DATE: &'static str = "%Y%m%d";

lazy_static! {
    pub static ref AWS_URL_RE: Regex = Regex::new(r"^https?://(?P<endpoint>[a-zA-Z0-9\-_]+)\.(?P<region>[a-z0-9\-]+)\.(?P<service>[a-z]+)\.amazonaws.com$").unwrap();
    pub static ref SIGNED_HEADERS: Vec<HeaderName> = vec![
        header::HOST,
        header::CONTENT_TYPE,
        header::CONTENT_LENGTH,
        HeaderName::from_static("x-amz-date"),
        HeaderName::from_static("X-Amz-Security-Token"),
        HeaderName::from_static("x-amz-content-sha256"),
    ];

    pub static ref DROPPED_HEADERS: Vec<HeaderName> = vec![
        header::CONNECTION,
        header::HOST,
        header::AUTHORIZATION
    ];

}
