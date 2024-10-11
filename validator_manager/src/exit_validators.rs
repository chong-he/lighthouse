use crate::{common::vc_http_client, DumpConfig};
use clap::{Arg, ArgAction, ArgMatches, Command};
use eth2::{BeaconNodeHttpClient, SensitiveUrl, Timeouts};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;
use types::PublicKeyBytes;

pub const CMD: &str = "exit";
pub const BEACON_URL_FLAG: &str = "beacon-node";
pub const VALIDATORS_FILE_FLAG: &str = "validators-file";
pub const VC_URL_FLAG: &str = "vc-url";
pub const VC_TOKEN_FLAG: &str = "vc-token";
pub const VALIDATOR_FLAG: &str = "validators";

pub fn cli_app() -> Command {
    Command::new(CMD)
        .about("Exit validator using the HTTP API for a given validator keystore.")
        .arg(
            Arg::new(BEACON_URL_FLAG)
                .long(BEACON_URL_FLAG)
                .value_name("NETWORK_ADDRESS")
                .help("Address to a beacon node HTTP API")
                .default_value("http://localhost:5052")
                .action(ArgAction::Set)
                .display_order(0),
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
    pub beacon_url: Option<SensitiveUrl>,
}

impl ExitConfig {
    fn from_cli(matches: &ArgMatches) -> Result<Self, String> {
        Ok(Self {
            vc_url: clap_utils::parse_required(matches, VC_URL_FLAG)?,
            vc_token_path: clap_utils::parse_required(matches, VC_TOKEN_FLAG)?,
            validators_to_exit: clap_utils::parse_required(matches, VALIDATOR_FLAG)?,
            beacon_url: clap_utils::parse_optional(matches, BEACON_URL_FLAG)?,
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
        validators_to_exit,
        beacon_url,
    } = config;

    let (http_client, validators) = vc_http_client(vc_url.clone(), &vc_token_path).await?;

    // Check that the validators_to_exit is in the validator client
    if !validators
        .iter()
        .any(|validator| validator.validating_pubkey == validators_to_exit)
    {
        return Err(format!("Validator {} doesn't exist", validators_to_exit));
    }

    // let exit_epoch: Option<Epoch>;

    let exit_message = http_client
        .post_validator_voluntary_exit(&validators_to_exit, None)
        .await
        .map_err(|e| format!("Failed to generate voluntary exit message: {}", e))?;

    println!("Voluntary exit message: {:?}", exit_message.data);

    let beacon_node = if let Some(beacon_url) = beacon_url {
        BeaconNodeHttpClient::new(
            SensitiveUrl::parse(beacon_url.as_ref())
                .map_err(|e| format!("Failed to parse beacon http server: {:?}", e))?,
            Timeouts::set_all(Duration::from_secs(12)),
        )
    } else {
        return Err("Beacon URL is not provided".into());
    };

    let voluntary_exit = beacon_node
        .post_beacon_pool_voluntary_exits(&exit_message.data)
        .await;

    match voluntary_exit {
        Ok(()) => println!(
            "Successfully published voluntary exit for validator {}",
            validators_to_exit
        ),
        Err(e) => println!("Failed to publish voluntary exit: {}", e),
    }

    // println!("{:?}", voluntary_exit);

    Ok(())
}
