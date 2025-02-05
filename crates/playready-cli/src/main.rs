use std::path::{Path, PathBuf};

use isahc::{ReadResponseExt, Request, RequestExt};
use playready::{cdm::Cdm, Device, Pssh};

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

const TEST_PSSH: &str = concat!(
    "AAADfHBzc2gAAAAAmgTweZhAQoarkuZb4IhflQAAA1xcAwAAAQABAFIDPABXAFIATQBIAEUAQQBEAEUAUgAgAHgAbQBsAG4AcwA9ACIAaAB0AH",
    "QAcAA6AC8ALwBzAGMAaABlAG0AYQBzAC4AbQBpAGMAcgBvAHMAbwBmAHQALgBjAG8AbQAvAEQAUgBNAC8AMgAwADAANwAvADAAMwAvAFAAbABh",
    "AHkAUgBlAGEAZAB5AEgAZQBhAGQAZQByACIAIAB2AGUAcgBzAGkAbwBuAD0AIgA0AC4AMAAuADAALgAwACIAPgA8AEQAQQBUAEEAPgA8AFAAUg",
    "BPAFQARQBDAFQASQBOAEYATwA+ADwASwBFAFkATABFAE4APgAxADYAPAAvAEsARQBZAEwARQBOAD4APABBAEwARwBJAEQAPgBBAEUAUwBDAFQA",
    "UgA8AC8AQQBMAEcASQBEAD4APAAvAFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBJAEQAPgA0AFIAcABsAGIAKwBUAGIATgBFAFMAOAB0AE",
    "cAawBOAEYAVwBUAEUASABBAD0APQA8AC8ASwBJAEQAPgA8AEMASABFAEMASwBTAFUATQA+AEsATABqADMAUQB6AFEAUAAvAE4AQQA9ADwALwBD",
    "AEgARQBDAEsAUwBVAE0APgA8AEwAQQBfAFUAUgBMAD4AaAB0AHQAcABzADoALwAvAHAAcgBvAGYAZgBpAGMAaQBhAGwAcwBpAHQAZQAuAGsAZQ",
    "B5AGQAZQBsAGkAdgBlAHIAeQAuAG0AZQBkAGkAYQBzAGUAcgB2AGkAYwBlAHMALgB3AGkAbgBkAG8AdwBzAC4AbgBlAHQALwBQAGwAYQB5AFIA",
    "ZQBhAGQAeQAvADwALwBMAEEAXwBVAFIATAA+ADwAQwBVAFMAVABPAE0AQQBUAFQAUgBJAEIAVQBUAEUAUwA+ADwASQBJAFMAXwBEAFIATQBfAF",
    "YARQBSAFMASQBPAE4APgA4AC4AMQAuADIAMwAwADQALgAzADEAPAAvAEkASQBTAF8ARABSAE0AXwBWAEUAUgBTAEkATwBOAD4APAAvAEMAVQBT",
    "AFQATwBNAEEAVABUAFIASQBCAFUAVABFAFMAPgA8AC8ARABBAFQAQQA+ADwALwBXAFIATQBIAEUAQQBEAEUAUgA+AA==");

const TEST_SERVER_URL: &str =
    "https://test.playready.microsoft.com/service/rightsmanager.asmx?cfg=(persist:false,sl:2000)";

#[derive(Subcommand)]
enum Commands {
    /// Tests the .prd device by connecting to the demo server provided by Microsoft.
    TestDevice { path: PathBuf },
}

fn test_device(path: impl AsRef<Path>) -> Result<(), playready::Error> {
    let device = Device::from_prd(path)?;
    log::info!("Device: {}", device.name()?);
    log::info!("Security level: {}", device.security_level()?);
    log::info!(
        "Certificate validation: {}",
        device.verify_certificates().is_ok(),
    );

    let pssh = Pssh::from_b64(TEST_PSSH.as_bytes())?;
    let wrm_header = pssh.wrm_headers()[0].clone();

    let cdm = Cdm::from_device(device);
    let session = cdm.open_session();

    let challenge = session.get_license_challenge(wrm_header)?;

    let request = Request::post(TEST_SERVER_URL)
        .header("Content-Type", "text/xml; charset=utf-8")
        .body(challenge)
        .unwrap();
    let response = String::from_utf8(request.send().unwrap().bytes().unwrap()).unwrap();

    let keys = session.get_keys_from_challenge_response(response.as_str())?;

    log::info!("Content keys:");
    for (kid, ck) in &keys {
        log::info!("\t{kid}:{ck}");
    }

    Ok(())
}

fn main() {
    colog::default_builder()
        .filter(None, log::LevelFilter::Info)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::TestDevice { path } => test_device(path)
            .inspect_err(|e| log::error!("Test failed with an error: {e:?}"))
            .unwrap_or_default(),
    }
}
