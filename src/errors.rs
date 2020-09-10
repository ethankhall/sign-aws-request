use error_enum::{ErrorContainer, ErrorEnum, PrettyError};

#[derive(Debug, PartialEq, Eq, ErrorContainer)]
pub enum CliErrors {
    Unknown(UnknownErrors),
    Config(ConfigErrors),
}

#[derive(Debug, PartialEq, Eq, ErrorEnum)]
#[error_enum(prefix = "UNKNOWN")]
pub enum UnknownErrors {
    #[error_enum(description = "Unknown Error")]
    Unknown(String),
}

#[derive(Debug, PartialEq, Eq, ErrorEnum)]
#[error_enum(prefix = "CFG")]
pub enum ConfigErrors {
    #[error_enum(description = "Invalid Aws Target")]
    InvalidAwsTarget(String),
}
