use musig2::secp256k1;
use musig2::KeyAggContext;

// Use musig2's re-exported secp types to avoid version conflicts
use musig2::secp::{Point, Scalar};

/// An operator's signing keypair (using musig2's secp types).
pub struct OperatorKey {
    pub secret: Scalar,
    pub public: Point,
}

/// The set of operator keys and their aggregated MuSig2 context.
pub struct OperatorSet {
    pub keys: Vec<OperatorKey>,
    pub key_agg_ctx: KeyAggContext,
}

impl OperatorSet {
    /// Create an operator set with `n` randomly generated keys.
    pub fn generate(n: usize) -> Self {
        let keys: Vec<OperatorKey> = (0..n)
            .map(|_| {
                // Generate a random 32-byte secret key
                let mut bytes = [0u8; 32];
                loop {
                    rand::fill(&mut bytes);
                    if let Ok(sk) = secp256k1::SecretKey::from_byte_array(bytes) {
                        let secret: Scalar = sk.into();
                        let public = secret.base_point_mul();
                        return OperatorKey { secret, public };
                    }
                }
            })
            .collect();

        let pubkeys = keys.iter().map(|k| k.public);
        let key_agg_ctx = KeyAggContext::new(pubkeys).expect("valid pubkeys");

        OperatorSet { keys, key_agg_ctx }
    }

    /// The aggregated public key as a bitcoin-compatible XOnlyPublicKey.
    pub fn aggregate_xonly(&self) -> bitcoin::XOnlyPublicKey {
        let agg_point: Point = self.key_agg_ctx.aggregated_pubkey();
        point_to_xonly(agg_point)
    }

    pub fn n_operators(&self) -> usize {
        self.keys.len()
    }
}

/// Convert a musig2 secp Point to a bitcoin XOnlyPublicKey.
pub fn point_to_xonly(point: Point) -> bitcoin::XOnlyPublicKey {
    // musig2 uses secp256k1 0.31, bitcoin uses 0.30
    // Convert via serialization
    let pk: secp256k1::PublicKey = point.into();
    let (xonly, _parity) = pk.x_only_public_key();
    let bytes = xonly.serialize();
    bitcoin::XOnlyPublicKey::from_slice(&bytes).expect("valid 32-byte x-only key")
}
