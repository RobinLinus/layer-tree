//! User authentication: Schnorr signature verification for transfers and withdrawals.
//!
//! Transfer message format: SHA256(to_pubkey_hex || amount_sats_le8 || nonce_le8)
//! Withdrawal message format: SHA256(dest_address || amount_sats_le8 || nonce_le8)
//!
//! Users sign the message with their x-only private key using BIP-340 Schnorr.

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{schnorr, Message, Secp256k1, XOnlyPublicKey};

/// Verify a Schnorr signature on a transfer message.
///
/// The message is: SHA256(to_pubkey_hex || amount_sats as 8-byte LE || nonce as 8-byte LE)
pub fn verify_transfer_sig(
    from_pubkey_hex: &str,
    to_pubkey_hex: &str,
    amount_sats: u64,
    nonce: u64,
    signature_hex: &str,
) -> Result<(), String> {
    let pubkey = parse_xonly_pubkey(from_pubkey_hex)?;
    let sig = parse_schnorr_sig(signature_hex)?;

    let msg = build_transfer_message(to_pubkey_hex, amount_sats, nonce);
    let secp = Secp256k1::verification_only();

    secp.verify_schnorr(&sig, &msg, &pubkey)
        .map_err(|e| format!("invalid signature: {e}"))
}

/// Verify a Schnorr signature on a withdrawal message.
///
/// The message is: SHA256(dest_address || amount_sats as 8-byte LE || nonce as 8-byte LE)
pub fn verify_withdrawal_sig(
    pubkey_hex: &str,
    dest_address: &str,
    amount_sats: u64,
    nonce: u64,
    signature_hex: &str,
) -> Result<(), String> {
    let pubkey = parse_xonly_pubkey(pubkey_hex)?;
    let sig = parse_schnorr_sig(signature_hex)?;

    let msg = build_withdrawal_message(dest_address, amount_sats, nonce);
    let secp = Secp256k1::verification_only();

    secp.verify_schnorr(&sig, &msg, &pubkey)
        .map_err(|e| format!("invalid signature: {e}"))
}

/// Build the message that a user signs for a transfer.
pub fn build_transfer_message(to_pubkey_hex: &str, amount_sats: u64, nonce: u64) -> Message {
    let hash = sha256::Hash::hash(
        &[
            to_pubkey_hex.as_bytes(),
            &amount_sats.to_le_bytes(),
            &nonce.to_le_bytes(),
        ]
        .concat(),
    );
    Message::from_digest(*hash.as_ref())
}

/// Build the message that a user signs for a withdrawal.
pub fn build_withdrawal_message(dest_address: &str, amount_sats: u64, nonce: u64) -> Message {
    let hash = sha256::Hash::hash(
        &[
            dest_address.as_bytes(),
            &amount_sats.to_le_bytes(),
            &nonce.to_le_bytes(),
        ]
        .concat(),
    );
    Message::from_digest(*hash.as_ref())
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

    #[test]
    fn test_transfer_sign_and_verify() {
        let secp = Secp256k1::new();

        // Generate a keypair
        let mut secret_bytes = [0u8; 32];
        secret_bytes[31] = 1;
        let keypair = Keypair::from_seckey_slice(&secp, &secret_bytes).unwrap();
        let (xonly, _) = keypair.x_only_public_key();
        let from_pubkey_hex = hex_encode(&xonly.serialize());

        let to_pubkey_hex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let amount_sats = 50_000u64;
        let nonce = 1u64;

        // Sign
        let msg = build_transfer_message(to_pubkey_hex, amount_sats, nonce);
        let sig = secp.sign_schnorr(&msg, &keypair);
        let sig_hex = hex_encode(&sig.serialize());

        // Verify
        let result = verify_transfer_sig(&from_pubkey_hex, to_pubkey_hex, amount_sats, nonce, &sig_hex);
        assert!(result.is_ok(), "valid sig should pass: {result:?}");

        // Wrong amount should fail
        let result = verify_transfer_sig(&from_pubkey_hex, to_pubkey_hex, 99_999, nonce, &sig_hex);
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

        let dest_address = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
        let amount_sats = 25_000u64;
        let nonce = 42u64;

        let msg = build_withdrawal_message(dest_address, amount_sats, nonce);
        let sig = secp.sign_schnorr(&msg, &keypair);
        let sig_hex = hex_encode(&sig.serialize());

        let result = verify_withdrawal_sig(&pubkey_hex, dest_address, amount_sats, nonce, &sig_hex);
        assert!(result.is_ok());

        // Wrong address should fail
        let result = verify_withdrawal_sig(&pubkey_hex, "wrong_address", amount_sats, nonce, &sig_hex);
        assert!(result.is_err());
    }
}
