// Copyright 2026, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Parse and Fetch attestation keys data

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use std::fs;
use xml::{
    attribute::OwnedAttribute,
    reader::{EventReader, XmlEvent},
};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AttestationKey {
    pub(crate) algorithm: String,
    pub(crate) private_key: Vec<u8>,
    pub(crate) certs: Vec<Vec<u8>>,
}

pub(crate) fn get_attestation_keys(file: fs::File) -> Result<Vec<AttestationKey>> {
    let mut xml_events_reader = EventReader::new(file);
    let mut attestation_keys = vec![];

    loop {
        match xml_events_reader.next()? {
            XmlEvent::StartElement { name, attributes, .. }
                if name.local_name.as_str() == "Key" =>
            {
                let algorithm = get_value_from_attribute(attributes, "algorithm")
                    .context("parsing algorithm")?;
                let private_key =
                    parse_private_key(&mut xml_events_reader).context("parsing private key")?;

                let attestation_key = AttestationKey { algorithm, private_key, certs: vec![] };

                attestation_keys.push(attestation_key);
            }
            XmlEvent::EndDocument => break,
            _ => continue,
        }
    }

    Ok(attestation_keys)
}

fn get_value_from_attribute(attributes: Vec<OwnedAttribute>, label: &str) -> Result<String> {
    attributes
        .into_iter()
        .find(|attribute| attribute.name.borrow().local_name == label)
        .map(|attribute| attribute.value)
        .ok_or(anyhow!("Missing attribute {}", label))
}

fn parse_private_key(xml_reader: &mut EventReader<fs::File>) -> Result<Vec<u8>> {
    loop {
        match xml_reader.next()? {
            XmlEvent::StartElement { name, attributes, .. }
                if name.local_name.as_str() == "PrivateKey" =>
            {
                let format = get_value_from_attribute(attributes, "format")?;
                let event = xml_reader.next()?;
                if let XmlEvent::Characters(text) = event {
                    return decode_to_der(format, text);
                }
                bail!("PrivateKey Value not found")
            }
            XmlEvent::EndDocument => bail!("Unexpected end of document"),
            _ => continue,
        }
    }
}

fn decode_to_der(format: String, characters: String) -> Result<Vec<u8>> {
    match format.as_str() {
        "pem" | "iecs" => base64_to_der(characters),
        unknown_format => bail!("Invalid format {}", unknown_format),
    }
}

fn base64_to_der(content: String) -> anyhow::Result<Vec<u8>> {
    let base64_content = content
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with("---"))
        .collect::<String>();
    Ok(general_purpose::STANDARD.decode(base64_content)?)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn validate_get_attestation_keys() -> Result<()> {
        let file = fs::File::open("set_attestation_key/keymaster_soft_attestation_keys.xml")?;
        let private_key = "MIICXQIBAAKBgQDAgyPcVogbuDAgafWwhWHG7r5/BeL1qEIEir6LR752/q7yXPKbKvoyABQWAUKZiaFfz8aBXrNjWDwv0vIL5Jgyg92BSxbX4YVBeuVKvClqOm21wAQIO2jFVsHwIzmRZBmGTVC3TUCuykhMdzVsiVoMJ1q/rEmdXX0jYvKcXgLocQIDAQABAoGBAL6GCwuZqAKm+xpZQ4p7txUGWwmjbcbpysxr88AsNNfXnpTGYGQo2Ix7f2V3wc3qZAdKvo5yht8fCBHclygmCGjeldMu/Ja20IT/JxpfYN78xwPno45uKbqaPF/CwoB2tqiWrx0014gozpvdsfNPnJQEQweBKY4gExZyW728mTpBAkEA4cbZJ2RsCRbsNoJtWUmDdAwh8bB0xKGlmGfGaXlchdPcRkxbkp6Uv7NODcxQFLEPEzQat/3V9gQU0qMmytQcxQJBANpIWZd4XNVjD7D9jFJU+Y5TjhiYOq6ea35qWntdNDdVuSGOvUAyDSg4fXifdvohi8wti2il9kGPu+ylF5qzr70CQFD+/DJklVlhbtZTThVFCTKdk6PYENvlvbmCKSz3i9i624Agro1X9LcdBThv/p6dsnHKNHejSZnbdvjl7OnA1J0CQBW3TPJ8zv+Ls2vwTZ2DRrCaL3DS9EObDyasfgP36dH3fUuRX9KbKCPwOstdUgDghX/yqAPpPu6W1iNc6VRCvCECQQCQp0XaiXCyzWSWYDJCKMX4KFb/1mW6moXI1g8bi+5xfs0scurgHa2GunZU1M9FrbXx8rMdn4Eiz6XxpVcPmy0l";
        let expected_private_key = general_purpose::STANDARD.decode(private_key)?;
        let attestation_keys = get_attestation_keys(file)?;
        assert_eq!(attestation_keys.len(), 2);
        let expected_attestation_key_0 = AttestationKey {
            algorithm: "rsa".to_string(),
            private_key: expected_private_key,
            certs: vec![],
        };
        assert_eq!(attestation_keys[0], expected_attestation_key_0);
        Ok(())
    }
}
