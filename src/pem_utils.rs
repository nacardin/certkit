/// Convert DER‑encoded data into a PEM‑encoded string with the provided label.
pub fn der_to_pem(der: &[u8], label: &str) -> String {
    let pem = pem::Pem::new(label, der);
    pem::encode_config(&pem, pem::EncodeConfig::new())
}

/// Convert a PEM‑encoded string to DER‑encoded bytes.
pub fn pem_to_der(pem_str: &str) -> Result<Vec<u8>, pem::PemError> {
    let pem = pem::parse(pem_str)?;
    Ok(pem.contents().to_vec())
}
