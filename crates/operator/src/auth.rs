//! User authentication: Schnorr signature verification for transfers and withdrawals.
//!
//! Message formats are defined in `layer_tree_core::blockchain`:
//! - Transfer:   SHA256(to_pubkey_32_bytes || amount_le8 || nonce_le8)
//! - Withdrawal: SHA256(from_pubkey_32_bytes || amount_le8 || nonce_le8)
//!
//! Users sign the message with their x-only private key using BIP-340 Schnorr.

use bitcoin::secp256k1::{schnorr, Secp256k1, XOnlyPublicKey};

/// Verify a Schnorr signature on a transfer message.
///
/// Message format must match `blockchain::transfer_message`:
/// SHA256(to_pubkey_32_bytes || amount_le8 || nonce_le8)
pub fn verify_transfer_sig(
    from_pubkey_hex: &str,
    to_pubkey_hex: &str,
    amount_sats: u64,
    nonce: u64,
    signature_hex: &str,
) -> Result<(), String> {
    let pubkey = parse_xonly_pubkey(from_pubkey_hex)?;
    let to_pubkey = parse_xonly_pubkey(to_pubkey_hex)?;
    let sig = parse_schnorr_sig(signature_hex)?;

    let msg = layer_tree_core::blockchain::transfer_message(&to_pubkey, amount_sats, nonce);
    let secp = Secp256k1::verification_only();

    secp.verify_schnorr(&sig, &msg, &pubkey)
        .map_err(|e| format!("invalid signature: {e}"))
}

/// Verify a Schnorr signature on a withdrawal message.
///
/// Message format must match `blockchain::withdrawal_message`:
/// SHA256(pubkey_32_bytes || amount_le8 || nonce_le8)
pub fn verify_withdrawal_sig(
    pubkey_hex: &str,
    _dest_address: &str,
    amount_sats: u64,
    nonce: u64,
    signature_hex: &str,
) -> Result<(), String> {
    let pubkey = parse_xonly_pubkey(pubkey_hex)?;
    let sig = parse_schnorr_sig(signature_hex)?;

    let msg = layer_tree_core::blockchain::withdrawal_message(&pubkey, amount_sats, nonce);
    let secp = Secp256k1::verification_only();

    secp.verify_schnorr(&sig, &msg, &pubkey)
        .map_err(|e| format!("invalid signature: {e}"))
}

fn parse_xonly_pubkey(hex: &str) -> Result<XOnlyPublicKey, String> {
    let bytes = hex_decode(hex)?;
    if bytes.len() != 32 {
        return Err(format!("pubkey must be 32 bytes, got {}", bytes.len()));
    }
    XOnlyPublicKey::from_slice(&bytes).map_err(|e| format!("invalid pubkey: {e}"))
}

fn parse_schnorr_sig(hex: &str) -> Result<schnorr::Signature, String> {
    let bytes = hex_decode(hex)?;
    if bytes.len() != 64 {
        return Err(format!("signature must be 64 bytes, got {}", bytes.len()));
    }
    schnorr::Signature::from_slice(&bytes).map_err(|e| format!("invalid signature: {e}"))
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd-length hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Secp256k1};
    use layer_tree_core::blockchain::{transfer_message, withdrawal_message};

    #[test]
    fn test_transfer_sign_and_verify() {
        let secp = Secp256k1::new();

        let mut secret_bytes = [0u8; 32];
        secret_bytes[31] = 1;
        let keypair = Keypair::from_seckey_slice(&secp, &secret_bytes).unwrap();
        let (xonly, _) = keypair.x_only_public_key();
        let from_pubkey_hex = hex_encode(&xonly.serialize());

        // Use a valid x-only pubkey for "to"
        let mut to_bytes = [0u8; 32];
        to_bytes[31] = 2;
        let to_kp = Keypair::from_seckey_slice(&secp, &to_bytes).unwrap();
        let (to_xonly, _) = to_kp.x_only_public_key();
        let to_pubkey_hex = hex_encode(&to_xonly.serialize());
        let amount_sats = 50_000u64;
        let nonce = 1u64;

        // Sign using the canonical message format
        let msg = transfer_message(&to_xonly, amount_sats, nonce);
        let sig = secp.sign_schnorr(&msg, &keypair);
        let sig_hex = hex_encode(&sig.serialize());

        // Verify
        let result = verify_transfer_sig(&from_pubkey_hex, &to_pubkey_hex, amount_sats, nonce, &sig_hex);
        assert!(result.is_ok(), "valid sig should pass: {result:?}");

        // Wrong amount should fail
        let result = verify_transfer_sig(&from_pubkey_hex, &to_pubkey_hex, 99_999, nonce, &sig_hex);
        assert!(result.is_err());
    }

    #[test]
    fn test_withdrawal_sign_and_verify() {
        let secp = Secp256k1::new();

        let mut secret_bytes = [0u8; 32];
        secret_bytes[31] = 2;
        let keypair = Keypair::from_seckey_slice(&secp, &secret_bytes).unwrap();
        let (xonly, _) = keypair.x_only_public_key();
        let pubkey_hex = hex_encode(&xonly.serialize());

        let dest_address = "512000112233445566778899aabbccddeeff00112233445566778899aabbccddee";
        let amount_sats = 25_000u64;
        let nonce = 42u64;

        // Sign using the canonical message format (uses pubkey, not dest_address)
        let msg = withdrawal_message(&xonly, amount_sats, nonce);
        let sig = secp.sign_schnorr(&msg, &keypair);
        let sig_hex = hex_encode(&sig.serialize());

        let result = verify_withdrawal_sig(&pubkey_hex, dest_address, amount_sats, nonce, &sig_hex);
        assert!(result.is_ok());

        // Wrong amount should fail
        let result = verify_withdrawal_sig(&pubkey_hex, dest_address, 99_999, nonce, &sig_hex);
        assert!(result.is_err());
    }
}
