use xml_builder::{XMLElement, XMLError};

pub fn render(element: &XMLElement) -> Result<Vec<u8>, XMLError> {
    let mut ret = Vec::<u8>::new();
    element.render(&mut ret, false, false, false, true)?;
    Ok(ret)
}

pub fn build_cipher_data(b64_chain: String) -> Result<XMLElement, XMLError> {
    let mut data = XMLElement::new("Data");

    let certificate_chains = {
        let mut certificate_chains = XMLElement::new("CertificateChains");

        let certificate_chain = {
            let mut certificate_chain = XMLElement::new("CertificateChain");
            certificate_chain.add_text(b64_chain)?;
            certificate_chain
        };
        certificate_chains.add_child(certificate_chain)?;

        certificate_chains
    };
    data.add_child(certificate_chains)?;

    let features = {
        let mut features = XMLElement::new("Features");

        let feature = {
            let mut feature = XMLElement::new("Feature");
            feature.add_attribute("Name", "AESCBC");
            feature.add_text(String::from("\"\""))?;

            feature
        };
        features.add_child(feature)?;

        let ree = {
            let mut ree = XMLElement::new("REE");
            let aescbcs = XMLElement::new("AESCBCS");

            ree.add_child(aescbcs)?;
            ree
        };
        features.add_child(ree)?;

        features
    };
    data.add_child(features)?;

    Ok(data)
}

pub fn build_signed_info(digest_value: String) -> Result<XMLElement, XMLError> {
    let mut signed_info = XMLElement::new("SignedInfo");
    signed_info.add_attribute("xmlns", "http://www.w3.org/2000/09/xmldsig#");

    let mut canonicalization_method = XMLElement::new("CanonicalizationMethod");
    canonicalization_method.add_attribute(
        "Algorithm",
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    );

    let mut signature_method = XMLElement::new("SignatureMethod");
    signature_method.add_attribute(
        "Algorithm",
        "http://schemas.microsoft.com/DRM/2007/03/protocols#ecdsa-sha256",
    );

    let reference = {
        let mut reference = XMLElement::new("Reference");
        reference.add_attribute("URI", "#SignedData");

        let digest_method = {
            let mut digest_method = XMLElement::new("DigestMethod");
            digest_method.add_attribute(
                "Algorithm",
                "http://schemas.microsoft.com/DRM/2007/03/protocols#sha256",
            );
            digest_method
        };
        reference.add_child(digest_method)?;

        let digest_value_tag = {
            let mut digest_value_tag = XMLElement::new("DigestValue");
            digest_value_tag.add_text(digest_value)?;
            digest_value_tag
        };
        reference.add_child(digest_value_tag)?;

        reference
    };

    signed_info.add_child(canonicalization_method)?;
    signed_info.add_child(signature_method)?;
    signed_info.add_child(reference)?;

    Ok(signed_info)
}

pub fn build_digest_content(
    protocol_version: String,
    client_version: String,
    client_time: String,
    wrm_header: String,
    nonce: String,
    wmrm_cipher: String,
    cert_cipher: String,
) -> Result<XMLElement, XMLError> {
    let mut la = XMLElement::new("LA");

    la.add_attribute(
        "xmlns",
        "http://schemas.microsoft.com/DRM/2007/03/protocols",
    );
    la.add_attribute("Id", "SignedData");
    la.add_attribute("xml:space", "preserve");

    let mut version = XMLElement::new("Version");
    version.add_text(protocol_version)?;

    let mut content_header = XMLElement::new("ContentHeader");
    content_header.add_text(wrm_header)?;

    let client_info = {
        let mut client_info = XMLElement::new("CLIENTINFO");
        let client_version_tag = {
            let mut client_version_tag = XMLElement::new("CLIENTVERSION");
            client_version_tag.add_text(client_version)?;
            client_version_tag
        };
        client_info.add_child(client_version_tag)?;
        client_info
    };

    let mut license_nonce = XMLElement::new("LicenseNonce");
    license_nonce.add_text(nonce)?;

    let mut client_time_tag = XMLElement::new("ClientTime");
    client_time_tag.add_text(client_time)?;

    let encrypted_data = {
        let mut encrypted_data = XMLElement::new("EncryptedData");
        encrypted_data.add_attribute("xmlns", "http://www.w3.org/2001/04/xmlenc#");
        encrypted_data.add_attribute("Type", "http://www.w3.org/2001/04/xmlenc#Element");

        let encryption_method = {
            let mut encryption_method = XMLElement::new("EncryptionMethod");
            encryption_method
                .add_attribute("Algorithm", "http://www.w3.org/2001/04/xmlenc#aes128-cbc");
            encryption_method
        };
        encrypted_data.add_child(encryption_method)?;

        let key_info = {
            let mut key_info = XMLElement::new("KeyInfo");
            key_info.add_attribute("xmlns", "http://www.w3.org/2000/09/xmldsig#");

            let encrypted_key = {
                let mut encrypted_key = XMLElement::new("EncryptedKey");
                encrypted_key.add_attribute("xmlns", "http://www.w3.org/2001/04/xmlenc#");

                let encryption_method = {
                    let mut encryption_method = XMLElement::new("EncryptionMethod");
                    encryption_method.add_attribute(
                        "Algorithm",
                        "http://schemas.microsoft.com/DRM/2007/03/protocols#ecc256",
                    );
                    encryption_method
                };
                encrypted_key.add_child(encryption_method)?;

                let key_info = {
                    let mut key_info = XMLElement::new("KeyInfo");
                    key_info.add_attribute("xmlns", "http://www.w3.org/2000/09/xmldsig#");

                    let key_name = {
                        let mut key_name = XMLElement::new("KeyName");
                        key_name.add_text(String::from("WMRMServer"))?;
                        key_name
                    };
                    key_info.add_child(key_name)?;

                    key_info
                };
                encrypted_key.add_child(key_info)?;

                let cipher_data = {
                    let mut cipher_data = XMLElement::new("CipherData");
                    let cipher_value = {
                        let mut cipher_value = XMLElement::new("CipherValue");
                        cipher_value.add_text(wmrm_cipher)?;
                        cipher_value
                    };
                    cipher_data.add_child(cipher_value)?;
                    cipher_data
                };

                encrypted_key.add_child(cipher_data)?;
                encrypted_key
            };

            key_info.add_child(encrypted_key)?;
            key_info
        };
        encrypted_data.add_child(key_info)?;

        let cipher_data = {
            let mut cipher_data = XMLElement::new("CipherData");
            let cipher_value = {
                let mut cipher_value = XMLElement::new("CipherValue");
                cipher_value.add_text(cert_cipher)?;
                cipher_value
            };
            cipher_data.add_child(cipher_value)?;
            cipher_data
        };

        encrypted_data.add_child(cipher_data)?;
        encrypted_data
    };

    la.add_child(version)?;
    la.add_child(content_header)?;
    la.add_child(client_info)?;
    la.add_child(license_nonce)?;
    la.add_child(client_time_tag)?;
    la.add_child(encrypted_data)?;

    Ok(la)
}

pub fn build_license_challenge(
    la_content: XMLElement,
    signed_info: XMLElement,
    signature: String,
    public_key: String,
) -> Result<XMLElement, XMLError> {
    let mut envelope = XMLElement::new("soap:Envelope");
    envelope.add_attribute("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance");
    envelope.add_attribute("xmlns:xsd", "http://www.w3.org/2001/XMLSchema");
    envelope.add_attribute("xmlns:soap", "http://schemas.xmlsoap.org/soap/envelope/");

    let mut body = XMLElement::new("soap:Body");
    let mut acquire_license = XMLElement::new("AcquireLicense");
    let mut challenge1 = XMLElement::new("challenge");
    let mut challenge2 = XMLElement::new("Challenge");

    acquire_license.add_attribute(
        "xmlns",
        "http://schemas.microsoft.com/DRM/2007/03/protocols",
    );
    challenge2.add_attribute(
        "xmlns",
        "http://schemas.microsoft.com/DRM/2007/03/protocols/messages",
    );

    let signature_tag = {
        let mut signature_tag = XMLElement::new("Signature");
        signature_tag.add_attribute("xmlns", "http://www.w3.org/2000/09/xmldsig#");
        signature_tag.add_child(signed_info)?;

        let signature_value = {
            let mut signature_value = XMLElement::new("SignatureValue");
            signature_value.add_text(signature)?;

            signature_value
        };
        signature_tag.add_child(signature_value)?;

        let key_info = {
            let mut key_info = XMLElement::new("KeyInfo");
            key_info.add_attribute("xmlns", "http://www.w3.org/2000/09/xmldsig#");

            let key_value = {
                let mut key_value = XMLElement::new("KeyValue");

                let ecc_key_value = {
                    let mut ecc_key_value = XMLElement::new("ECCKeyValue");

                    let public_key_tag = {
                        let mut public_key_tag = XMLElement::new("PublicKey");
                        public_key_tag.add_text(public_key)?;
                        public_key_tag
                    };
                    ecc_key_value.add_child(public_key_tag)?;

                    ecc_key_value
                };
                key_value.add_child(ecc_key_value)?;

                key_value
            };
            key_info.add_child(key_value)?;

            key_info
        };
        signature_tag.add_child(key_info)?;

        signature_tag
    };

    challenge2.add_child(la_content)?;
    challenge2.add_child(signature_tag)?;

    challenge1.add_child(challenge2)?;
    acquire_license.add_child(challenge1)?;
    body.add_child(acquire_license)?;
    envelope.add_child(body)?;

    Ok(envelope)
}

pub fn parse_challenge_response(text: &str) -> Result<Vec<String>, roxmltree::Error> {
    let doc = roxmltree::Document::parse(text)?;

    Ok(doc
        .descendants()
        .filter(|n| n.has_tag_name("License"))
        .filter_map(|n| n.text().map(String::from))
        .collect::<Vec<_>>())
}
