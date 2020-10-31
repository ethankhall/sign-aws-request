use clap::Clap;
use dotenv::dotenv;
use log::error;

mod aws;
mod consts;
mod errors;
mod request;
mod serve;

#[derive(Clap, Debug)]
struct LoggingOpts {
    /// A level of verbosity, and can be used multiple times
    #[clap(short, long, parse(from_occurrences), group = "logging")]
    verbose: u64,

    /// Enable all logging
    #[clap(short, long, group = "logging")]
    debug: bool,

    /// Disable everything but error logging
    #[clap(short, long, group = "logging")]
    error: bool,
}
/// Proxy request to AWS, ans sign it along the way.
///
/// This tool is intended to sit in front of a specific AWS service,
/// sign the request for that service, and forward it to the service.
/// This makes it easy for tools that don't understand AWS to talk to
/// AWS.
#[derive(Clap, Debug)]
#[clap(author, about, version)]
struct Opts {
    #[clap(subcommand)]
    subcmd: SubCommand,
    #[clap(flatten)]
    logging_opts: LoggingOpts,
}

#[derive(Clap, Debug)]
enum SubCommand {
    Serve(ServeArgs),
}

#[derive(Clap, Debug)]
/// Sign any request with available AWS credentials, then forward it along to
/// the destination.
struct ServeArgs {
    #[clap()]
    destination: String,

    #[clap(long, default_value = "127.0.0.1:3000", env = "LISTEN_ADDRESS")]
    listen_address: String,

    #[clap(flatten)]
    logging_opts: LoggingOpts,
}

#[tokio::main]
pub async fn main() {
    dotenv().ok();

    let opt = Opts::parse();
    let result = match opt.subcmd {
        SubCommand::Serve(args) => crate::serve::serve(&args).await,
    };

    if let Err(e) = result {
        error!("Error: {}", e);
        std::process::exit(e.get_error_number().into());
    }
}

pub(crate) fn init_logger(logging_opts: &LoggingOpts) {
    let mut logger = loggerv::Logger::new();
    if logging_opts.debug {
        logger = logger
            .verbosity(10)
            .line_numbers(true)
            .add_module_path_filter(module_path!());
    } else if logging_opts.error {
        logger = logger.verbosity(0).add_module_path_filter(module_path!());
    } else {
        logger = logger
            .verbosity(logging_opts.verbose)
            .base_level(log::Level::Info)
            .line_numbers(true)
            .add_module_path_filter(module_path!());
    }

    logger.init().unwrap();
}
