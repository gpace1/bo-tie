//! Cryptographic Methods
//!
//! These are methods that can be used by either Bluetooth protocols or the Bluetooth controller.
//! Cryptography is only done within software, there is no usage of hardware peripherals except for
//! the systems random number generator. Cryptographic functions not defined within the Bluetooth
//! specification come from the [Rust Crypto group](https://github.com/RustCrypto).

use rand_core::{CryptoRng, RngCore};

/// The public key type for the P-256 curve
pub type PubKey = p256::PublicKey;

/// The private (Ephemeral Secret) key type for the P-256 curve
pub type PriKey = p256::ecdh::EphemeralSecret;

/// The Diffie-Hellman shared secret
type DHSharedSecret = [u8; 32];

/// 24-bit hash function
///
/// Used in random address creation and resolution.
pub fn ah(k: u128, r: [u8; 3]) -> [u8; 3] {
    let r_padded = <u128>::from(r[0]) | <u128>::from(r[1]) << (1 * 8) | <u128>::from(r[2]) << (2 * 8);

    let cypher_text = e(k, r_padded);

    [cypher_text as u8, (cypher_text >> 8) as u8, (cypher_text >> 16) as u8]
}

/// Security function *e*
///
/// This is the encrypted data generator for LE legacy and secure connections. It generates 128-bit
/// data from a 128-bit key using the AES-128 bit block cypher
/// (see [FIPS-197](https://en.wikipedia.org/wiki/FIPS_197)).
///
/// This is host version of this function and doesn't rely on the controller to encrypt the payload.
/// Whether or not this function is faster then the asynchronous version depends on the architecture
/// of your system in relation to the Bluetooth controller. However, it
/// is recommended to use this function if your target architecture supports the
/// [AES Instruction Set](https://en.wikipedia.org/wiki/AES_instruction_set).
///
/// # Note
/// While this function can be used for encryption of other l2cap connection channels, but it is
/// recommended to leave to controller to perform a connection channels encryption. This function
/// main purpose is for use with the security manager's pairing, and as a result it is inefficient
/// to call it constantly as it initializes a new AES cypher on each call.
pub fn e(key: u128, plain_text: u128) -> u128 {
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::{BlockEncrypt, KeyInit};

    let key_bytes = key.to_be_bytes();

    let cipher = aes::Aes128::new(GenericArray::from_slice(&key_bytes));

    let mut block = plain_text.to_be_bytes();

    cipher.encrypt_block(GenericArray::from_mut_slice(&mut block));

    <u128>::from_be_bytes(block)
}

/// AES-CMAC subkey generation algorithm
///
/// Derived from [The AES-CMAC Algorithm](https://datatracker.ietf.org/doc/rfc4493)
fn aes_cmac_subkey_gen(k: u128) -> (u128, u128) {
    const RB: u128 = 0x87;

    let l = e(k, 0);

    let k1 = if (l & (1 << 127)) == 0 { l << 1 } else { (l << 1) ^ RB };

    let k2 = if (k1 & (1 << 127)) == 0 {
        k1 << 1
    } else {
        (k1 << 1) ^ RB
    };

    (k1, k2)
}

fn aes_cmac_padding(r: &[u8]) -> u128 {
    let unpad = r
        .iter()
        .enumerate()
        .fold(0u128, |p, (i, v)| p | (<u128>::from(*v) << (8 * (15 - i))));

    unpad | (1 << (127 - (8 * r.len())))
}

/// Convert a slice of *plain text* with a length of 16 into a u128, big endian value.
///
/// The AES algorithm require that the plain text be in big endian order to produce a *cypher text*
/// that is also in big endian order.
fn to_u128_be(chunk_16_bytes: &[u8]) -> u128 {
    let mut c = [0u8; 16];

    c.clone_from_slice(chunk_16_bytes);

    <u128>::from_ne_bytes(c).to_be()
}

/// AES-CMAC algorithm
///
/// This Algorithm takes a AES-128 key along with a message in order to generate an authentication
/// code for the message.
///
/// This method is derived from [The AES-CMAC Algorithm](https://datatracker.ietf.org/doc/rfc4493).
pub fn aes_cmac_generate<T, V>(key: u128, msg: T) -> u128
where
    T: IntoIterator<Item = V>,
    V: core::borrow::Borrow<u8>,
{
    use crate::buffer::stack::LinearBuffer;

    macro_rules! chunk {
        ($iterator:expr, $size:expr) => {{
            let mut lb = LinearBuffer::<CHUNK_SIZE, u8>::new();

            (&mut $iterator)
                .take(CHUNK_SIZE)
                .for_each(|b| lb.try_push(*b.borrow()).unwrap());

            lb
        }};
    }

    const CHUNK_SIZE: usize = 16;

    let (k1, k2) = aes_cmac_subkey_gen(key);

    // need to fuse iterator to ensure `None`
    // is not proceeded by `Some(T::Item)`.
    let mut iterator = msg.into_iter().fuse();

    let first_chunk = chunk!(iterator, CHUNK_SIZE);

    let (x, last) = match first_chunk.len() {
        CHUNK_SIZE => {
            let mut x = 0;

            let mut current_chunk = first_chunk;

            let mut next_chunk = chunk!(iterator, CHUNK_SIZE);

            loop {
                if next_chunk.len() == 0 {
                    break (x, Some(current_chunk));
                }

                x = e(key, x ^ to_u128_be(&current_chunk));

                if next_chunk.len() < CHUNK_SIZE {
                    break (x, Some(next_chunk));
                }

                current_chunk = next_chunk;

                next_chunk = chunk!(iterator, CHUNK_SIZE);
            }
        }
        0 => (0, None),
        _ => (0, Some(first_chunk)),
    };

    let opt_len = last.as_ref().map(|l| l.len());

    let y = match (last, opt_len) {
        (None, _) => aes_cmac_padding(&[]) ^ k2 ^ x,
        (Some(last), Some(16)) => to_u128_be(&last) ^ k1 ^ x,
        (Some(last), _) => aes_cmac_padding(&last) ^ k2 ^ x,
    };

    e(key, y)
}

/// Verification for AES-CMAC
///
/// This method is used for verifying an `auth_code` given the `msg` and secret `key`.
pub fn aes_cmac_verify(key: u128, msg: &[u8], auth_code: u128) -> bool {
    auth_code == aes_cmac_generate(key, msg)
}

/// Generate the (private, public) key pair for an elliptic curve
///
/// This uses the systems random number generator to create the private key.
#[cfg(feature = "sys-rand")]
pub fn ecc_gen() -> (PriKey, PubKey) {
    ecc_gen_with(rand_core::OsRng)
}

/// Generate the (private, public) key pair for an elliptic curve using a provided random number generator.
///
/// This takes a random to generate the private key with. This random should either be a true random
/// number or a number generated from a cryptographically secure pseudorandom number generator for
/// elliptic curve cryptography.
pub fn ecc_gen_with(mut rand: impl CryptoRng + RngCore) -> (PriKey, PubKey) {
    let ephemeral_secret = PriKey::random(&mut rand);

    let public_key = PubKey::from(&ephemeral_secret);

    (ephemeral_secret, public_key)
}

/// Calculate the elliptic curve Diffie-Hellman shared secret from the provided public key
///
/// Both the secret key and public key are uncompressed. The public key is also just
/// the x and y coordinate, and there is no octet to indicate if it is compressed/uncompressed.
///
/// The return is the raw x coordinate, so it is not uniformly random. It should go through a key
/// derivation function or cryptographic hash function before being used for a symmetric cipher.
pub fn ecdh(this_private_key: PriKey, peer_public_key: &PubKey) -> DHSharedSecret {
    let shared_secret = this_private_key.diffie_hellman(peer_public_key);

    let mut raw_secret_bytes = DHSharedSecret::default();

    raw_secret_bytes.copy_from_slice(shared_secret.raw_secret_bytes().as_slice());

    raw_secret_bytes
}

/// Generate a random `u128` value
#[cfg(feature = "sys-rand")]
pub fn rand_u128() -> u128 {
    use rand_core::OsRng;

    let mut bytes = [0u8; 16];

    OsRng.fill_bytes(&mut bytes);

    <u128>::from_ne_bytes(bytes)
}

/// Generate a nonce
#[cfg(feature = "sys-rand")]
pub fn nonce() -> u128 {
    rand_u128()
}

/// Tests
///
/// The much of the tests data can be retrieved from the end of the Security Manager specification,
/// but some of the tests data is unique. All the data (if the applicable function is implemented)
/// should be used here for testing.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_cmac_padding_test() {
        let b = [0x11, 0x22, 0x33];

        assert_eq!(0x1122_3380_0000_0000_0000_0000_0000_0000u128, aes_cmac_padding(&b));
    }

    /// The tests data was retrieved from [The AES-CMAC Algorithm](https://datatracker.ietf.org/doc/rfc4493)
    #[test]
    fn aes_cmac_subkey_gen_test() {
        let k = 0x2b7e1516_28aed2a6_abf71588_09cf4f3c;

        assert_eq!(0x7df76b0c_1ab899b3_3e42f047_b91b546f, e(k, 0));

        let (k1, k2) = aes_cmac_subkey_gen(k);

        assert_eq!(0xfbeed618_35713366_7c85e08f_7236a8de, k1);
        assert_eq!(0xf7ddac30_6ae266cc_f90bc11e_e46d513b, k2);
    }

    /// This test data was retrieved from [The AES-CMAC Algorithm](https://datatracker.ietf.org/doc/rfc4493)
    #[test]
    fn aes_cmac_gen_test() {
        let k = 0x2b7e1516_28aed2a6_abf71588_09cf4f3c;

        let m = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d,
            0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46,
            0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f,
            0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
        ];

        assert_eq!(0xbb1d6929_e9593728_7fa37d12_9b756746, aes_cmac_generate(k, &m[..0]));
        assert_eq!(0x070a16b4_6b4d4144_f79bdd9d_d04a287c, aes_cmac_generate(k, &m[..16]));
        assert_eq!(0xdfa66747_de9ae630_30ca3261_1497c827, aes_cmac_generate(k, &m[..40]));
        assert_eq!(0x51f0bebf_7e3b9d92_fc497417_79363cfe, aes_cmac_generate(k, &m));
    }
}
