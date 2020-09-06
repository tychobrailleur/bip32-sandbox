use hdwallet::{ExtendedPrivKey, ExtendedPubKey, KeyIndex};
use ed25519_bip32::{XPrv, DerivationScheme};

fn main() {

    // secp256k1

    let master_key = ExtendedPrivKey::random().unwrap();

    let normal_key_index = KeyIndex::Normal(0);
    let normal_child_priv_key = master_key.derive_private_key(normal_key_index).unwrap();

    let normal_child_public_key = ExtendedPubKey::from_private_key(&normal_child_priv_key);
    let derived_public_key = ExtendedPubKey::derive_public_key(&normal_child_public_key, KeyIndex::Normal(1000000));

    let normal_derived_private_key = normal_child_priv_key.derive_private_key(KeyIndex::Normal(1000000)).unwrap();
    let normal_derived_public_key = ExtendedPubKey::from_private_key(&normal_derived_private_key);


    println!("{:x?}", derived_public_key);
    println!("{:x?}", normal_derived_public_key);

    // Ed25519

    let bytes = [1u8; 96];
    let xprv = XPrv::normalize_bytes_force3rd(bytes);

    let xpriv_private_derived = xprv.derive(DerivationScheme::V2, 1000000);
    let xpub_from_xpriv = xprv.public();

    let xpub_derived_from_xpriv_derived = xpriv_private_derived.public();
    let xpub_derived_from_xpub_dervied = xpub_from_xpriv.derive(DerivationScheme::V2, 1000000);

    println!("{:x?}", xpub_derived_from_xpub_dervied);
    println!("{:x?}", xpub_derived_from_xpriv_derived);

}
