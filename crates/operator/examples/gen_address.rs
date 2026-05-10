use bitcoin::secp256k1::{Secp256k1, Keypair};
use bitcoin::key::TweakedPublicKey;

fn main() {
    let secp = Secp256k1::new();
    let mut sk_bytes = [0u8; 32];
    rand::fill(&mut sk_bytes);
    let keypair = Keypair::from_seckey_slice(&secp, &sk_bytes).unwrap();
    let (xonly, _) = keypair.x_only_public_key();

    let secret_hex: String = sk_bytes.iter().map(|b| format!("{b:02x}")).collect();
    let pubkey_hex: String = xonly.serialize().iter().map(|b| format!("{b:02x}")).collect();

    let address = bitcoin::Address::p2tr_tweaked(
        TweakedPublicKey::dangerous_assume_tweaked(xonly),
        bitcoin::Network::Regtest,
    );

    println!("secret_key:  {secret_hex}");
    println!("pubkey:      {pubkey_hex}");
    println!("address:     {address}");
}
