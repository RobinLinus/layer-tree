//! Operator key management: loading, generating, and aggregation.

use std::path::Path;

use musig2::secp::{Point, Scalar};
use musig2::secp256k1;
use musig2::KeyAggContext;

/// Load or generate the operator's secret key from a file.
///
/// If the file exists, reads 32 bytes as the secret key.
/// If the file doesn't exist, generates a random key and writes it.
pub fn load_or_generate_key(path: &str) -> Result<Scalar, Box<dyn std::error::Error>> {
    if Path::new(path).exists() {
        let bytes = std::fs::read(path)?;
        if bytes.len() != 32 {
            return Err(format!("key file must be exactly 32 bytes, got {}", bytes.len()).into());
        }
        let sk = secp256k1::SecretKey::from_byte_array(bytes.try_into().unwrap())?;
        Ok(sk.into())
    } else {
        // Generate and save with restrictive permissions
        let mut bytes = [0u8; 32];
        rand::fill(&mut bytes);
        let sk = secp256k1::SecretKey::from_byte_array(bytes)?;
        std::fs::write(path, bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(sk.into())
    }
}

/// Get the public key point from a secret scalar.
pub fn public_key(secret: &Scalar) -> Point {
    secret.base_point_mul()
}

/// Parse a hex-encoded compressed public key (33 bytes) into a Point.
pub fn parse_pubkey_hex(hex: &str) -> Result<Point, Box<dyn std::error::Error>> {
    let bytes = hex::decode(hex)?;
    let pk = secp256k1::PublicKey::from_slice(&bytes)?;
    Ok(pk.into())
}

/// Build a KeyAggContext from a list of public key points.
/// The order determines signer indices.
pub fn build_key_agg_ctx(pubkeys: &[Point]) -> Result<KeyAggContext, Box<dyn std::error::Error>> {
    let ctx = KeyAggContext::new(pubkeys.iter().copied())?;
    Ok(ctx)
}

/// Determine the signer index for a given public key in the set.
pub fn find_signer_index(pubkeys: &[Point], our_pubkey: &Point) -> Option<usize> {
    pubkeys.iter().position(|pk| pk == our_pubkey)
}

/// Simple hex encoding/decoding (avoid extra dependency).
mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if s.len() % 2 != 0 {
            return Err("odd-length hex string".to_string());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
            .collect()
    }

    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

pub use hex::encode as hex_encode;

/// Convert a musig2 Point to a bitcoin XOnlyPublicKey.
pub fn point_to_xonly(point: Point) -> bitcoin::XOnlyPublicKey {
    let pk: secp256k1::PublicKey = point.into();
    let (xonly, _parity) = pk.x_only_public_key();
    let bytes = xonly.serialize();
    bitcoin::XOnlyPublicKey::from_slice(&bytes).expect("valid 32-byte x-only key")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_gen_and_load() {
        let tmp = std::env::temp_dir().join("layer_tree_test_key.bin");
        let path = tmp.to_str().unwrap();

        // Clean up from previous runs
        let _ = std::fs::remove_file(path);

        // Generate
        let sk1 = load_or_generate_key(path).unwrap();
        assert!(std::path::Path::new(path).exists());

        // Load same key
        let sk2 = load_or_generate_key(path).unwrap();
        assert_eq!(sk1, sk2);

        // Cleanup
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_parse_pubkey_and_aggregation() {
        // Generate 3 keys
        let keys: Vec<Scalar> = (0..3)
            .map(|_| {
                let mut bytes = [0u8; 32];
                rand::fill(&mut bytes);
                let sk = secp256k1::SecretKey::from_byte_array(bytes).unwrap();
                sk.into()
            })
            .collect();

        let pubkeys: Vec<Point> = keys.iter().map(|s| s.base_point_mul()).collect();

        // Build key agg context
        let ctx = build_key_agg_ctx(&pubkeys).unwrap();
        let agg: Point = ctx.aggregated_pubkey();

        // Should find each signer's index
        for (i, pk) in pubkeys.iter().enumerate() {
            assert_eq!(find_signer_index(&pubkeys, pk), Some(i));
        }

        // Aggregate key should be valid
        let xonly = point_to_xonly(agg);
        assert_eq!(xonly.serialize().len(), 32);
    }
}
