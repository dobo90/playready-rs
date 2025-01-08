# playready-rs

Rust port of [pyplayready](https://github.com/ready-dl/pyplayready).
Currently it does **not** support creating `.prd` files and device reprovisioning. Other functionality should be working fine.

As a proof of concept it has been integrated with Kodi. Implementation is available on [fork of inputstream.adaptive](https://github.com/dobo90/inputstream.adaptive/tree/Omega-ossdrm/src/decrypters/playready).

## Example usage:
```rust
use isahc::{ReadResponseExt, Request, RequestExt};
use playready::{cdm::Cdm, Device, Pssh};

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

fn main() {
    let device = Device::from_prd("device.prd").unwrap();
    println!("Device: {}", device.name().unwrap());
    println!("Security level: {}", device.security_level().unwrap());
    println!("Certificate validation: {:?}", device.verify_certificates(),);

    let pssh = Pssh::from_b64(TEST_PSSH.as_bytes()).unwrap();
    let wrm_header = pssh.wrm_headers()[0].clone();

    let cdm = Cdm::from_device(device);
    let session = cdm.open_session();

    let challenge = session.get_license_challenge(wrm_header).unwrap();

    let request = Request::post(TEST_SERVER_URL)
        .header("Content-Type", "text/xml; charset=utf-8")
        .body(challenge)
        .unwrap();
    let response = String::from_utf8(request.send().unwrap().bytes().unwrap()).unwrap();

    let keys = session
        .get_keys_from_challenge_response(response.as_str())
        .unwrap();

    println!("Content keys:");
    for (kid, ck) in &keys {
        println!("{}:{}", hex::encode(kid), hex::encode(ck));
    }
}
```

It also contains a simple CLI to test your `.prd` file by connecting to Microsoft's test server.
```
$ cd crates/playready-cli
$ cargo run test-device /path/to/device.prd
[*] Device: Test Device
[*] Security level: 0000
[*] Certificate validation: true
[*] Content keys:
[*]     xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

## Documentation
Available at [GitHub pages](https://dobo90.github.io/playready-rs/playready/index.html).
