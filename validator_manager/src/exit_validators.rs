use crate::{common::vc_http_client, DumpConfig};
use clap::{Arg, ArgAction, ArgMatches, Command};
use clap_utils::FLAG_HEADER;
use eth2::SensitiveUrl;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use types::PublicKeyBytes;

pub const CMD: &str = "exit";
pub const VALIDATORS_FILE_FLAG: &str = "validators-file";
pub const VC_URL_FLAG: &str = "vc-url";
pub const VC_TOKEN_FLAG: &str = "vc-token";
pub const VALIDATOR_FLAG: &str = "validators";

pub fn cli_app() -> Command {
    Command::new(CMD)
        .about("Exit validator using the HTTP API for a given validator keystore.")
        .arg(
            Arg::new("help")
                .long("help")
                .short('h')
                .help("Prints help information")
                .action(ArgAction::HelpLong)
                .display_order(0)
                .help_heading(FLAG_HEADER),
        )
        .arg(
            Arg::new(VC_URL_FLAG)
                .long(VC_URL_FLAG)
                .value_name("HTTP_ADDRESS")
                .help(
                    "A HTTP(S) address of a validator client using the keymanager-API. \
                    If this value is not supplied then a 'dry run' will be conducted where \
                    no changes are made to the validator client.",
                )
                .default_value("http://localhost:5062")
                .requires(VC_TOKEN_FLAG)
                .action(ArgAction::Set)
                .display_order(0),
        )
        .arg(
            Arg::new(VC_TOKEN_FLAG)
                .long(VC_TOKEN_FLAG)
                .value_name("PATH")
                .help("The file containing a token required by the validator client.")
                .action(ArgAction::Set)
                .display_order(0),
        )
        .arg(
            Arg::new(VALIDATOR_FLAG)
                .long(VALIDATOR_FLAG)
                .value_name("STRING")
                .help("List of validators (pubkey) to exit.")
                .action(ArgAction::Set)
                .display_order(0),
        )
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ExitConfig {
    pub vc_url: SensitiveUrl,
    pub vc_token_path: PathBuf,
    pub validators_to_exit: PublicKeyBytes,
}

impl ExitConfig {
    fn from_cli(matches: &ArgMatches) -> Result<Self, String> {
        Ok(Self {
            vc_url: clap_utils::parse_required(matches, VC_URL_FLAG)?,
            vc_token_path: clap_utils::parse_required(matches, VC_TOKEN_FLAG)?,
            validators_to_exit: clap_utils::parse_required(matches, VALIDATOR_FLAG)?,
        })
    }
}

pub async fn cli_run(matches: &ArgMatches, dump_config: DumpConfig) -> Result<(), String> {
    let config = ExitConfig::from_cli(matches)?;
    if dump_config.should_exit_early(&config)? {
        Ok(())
    } else {
        run(config).await
    }
}

async fn run(config: ExitConfig) -> Result<(), String> {
    let ExitConfig {
        vc_url,
        vc_token_path,
        validators_to_exit: _,
    } = config;

    let (http_client, validators) = vc_http_client(vc_url.clone(), &vc_token_path).await?;

    // let exit_epoch: Option<Epoch> = 3000;
    // let exit_epoch: Option<Epoch>;

    for validator in &validators {
        let _signing_message =
            http_client.post_validator_voluntary_exit(&validator.validating_pubkey, None);
    }

    Ok(())
}
