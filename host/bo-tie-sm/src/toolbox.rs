//! The Cryptographic Toolbox
//!
//! This contains the functions listed in the Bluetooth specification (as well as some cypher
//! functions). These functions are derived from the Bluetooth Specification v5.0 | Vol 3, Part H,
//! section 2.2: *Cryptographic Toolbox*.
//!
//! It is generally not needed to use these functions directly as they tailor made for the Security
//! Manager protocol.
//!
//! # The Algorithms
//! The names of each algorithm match the names as stated in the Security Manager section of the
//! Host Volume of the Bluetooth Specification (Vol 3, Part H, Section 2.2).
//!
//! # Note
//! For the the functions defined in the specification, all array inputs need to be in big-endian
//! order.

use bo_tie_util::buffer::stack::LinearBuffer;
pub use bo_tie_util::cryptography::{
    aes_cmac_generate, aes_cmac_verify, ah, e, ecc_gen, ecdh, nonce, rand_u128, PriKey, PubKey,
};

/// The identifier for an uncompressed public key
const UNCOMPRESSED_PUB_KEY_TYPE: u8 = 0x4;

const PUB_KEY_BYTE_LEN: usize = 65;

/// The range in the public key bytes of the x part of the coordinate
const PUB_KEY_X_RANGE: core::ops::Range<usize> = 1..33;

/// The range in the public key bytes of the y part of the coordinate
const PUB_KEY_Y_RANGE: core::ops::Range<usize> = 33..65;

/// The Diffie-Hellman shared secret
pub(super) type DHSharedSecret = [u8; 32];

impl super::GetXOfP256Key for PubKey {
    fn x(&self) -> [u8; 32] {
        let encoded_point = elliptic_curve::sec1::EncodedPoint::<p256::NistP256>::from(self);

        let mut ret = [0; 32];

        ret.copy_from_slice(encoded_point.x().unwrap().as_slice());

        ret
    }
}

impl super::CommandData for PubKey {
    /// # Panics
    /// This will panic if `PubKey` is compressed
    fn into_command_format(self) -> LinearBuffer<65, u8> {
        let encoded_point = elliptic_curve::sec1::EncodedPoint::<p256::NistP256>::from(&self);

        let mut ret = LinearBuffer::new();

        ret.try_extend_from_slice(encoded_point.x().unwrap().as_slice())
            .unwrap();

        ret.try_extend_from_slice(encoded_point.y().unwrap().as_slice())
            .unwrap();

        // Reverse the keys from big endian to little endian
        ret[..32].reverse(); // x
        ret[32..64].reverse(); // y

        ret
    }

    fn try_from_command_format(icd: &[u8]) -> Result<Self, super::Error> {
        // The icd doesn't contain the compression byte indicator in Bluetooth's Security Manager
        // PDUs.
        if icd.len() == PUB_KEY_BYTE_LEN - 1 {
            let mut pub_key = alloc::vec::Vec::with_capacity(PUB_KEY_BYTE_LEN);

            pub_key.push(UNCOMPRESSED_PUB_KEY_TYPE);

            pub_key.extend_from_slice(icd);

            // Reverse the keys from little endian to big endian
            pub_key[PUB_KEY_X_RANGE].reverse();
            pub_key[PUB_KEY_Y_RANGE].reverse();

            PubKey::from_sec1_bytes(&pub_key).map_err(|_| super::Error::Format)
        } else {
            Err(super::Error::Size)
        }
    }
}

/// Phase 2 (LE legacy) confirm value function
///
/// # Inputs
/// - K: AES key
/// - r: plain text
/// - pres: 7 bytes
/// - preq: 7 bytes
/// - iat: 1 bit, mapped to a boolean
/// - ia: 6 bytes
/// - rat: 1 bit, mapped to a boolean
/// - ra: 6 bytes
///
/// ## Note
/// All inputs are masked down to the size stated above
pub fn c1(k: u128, r: u128, pres: u128, preq: u128, iat: bool, ia: u128, rat: bool, ra: u128) -> u128 {
    let p1 = c1_p1(pres, preq, iat, rat);

    let p2 = c1_p2(ia, ra);

    e(k, e(k, r ^ p1) ^ p2)
}

fn c1_p1(pres: u128, preq: u128, iat: bool, rat: bool) -> u128 {
    let iat_p = if iat { 1 } else { 0 };
    let rat_p = (if rat { 1 } else { 0 }) << (1 * 8);

    let pres_m = (0xFF_FFFF_FFFF_FFFF & pres) << (9 * 8);
    let preq_m = (0xFF_FFFF_FFFF_FFFF & preq) << (2 * 8);

    pres_m | preq_m | rat_p | iat_p
}

fn c1_p2(ia: u128, ra: u128) -> u128 {
    let ia_p = (0xFFFF_FFFF_FFFF & ia) << (6 * 8);
    let ra_p = 0xFFFF_FFFF_FFFF & ra;

    ia_p | ra_p
}

/// Phase 2 (LE legacy) short term key (STK) function
pub fn s1(k: u128, r1: u128, r2: u128) -> u128 {
    let r1_p = (0x0000_0000_0000_0000_FFFF_FFFF_FFFF_FFFF & r1) << 64;
    let r2_p = 0x0000_0000_0000_0000_FFFF_FFFF_FFFF_FFFF & r2;

    e(k, r1_p | r2_p)
}

/// Phase 2 (LE Secure) confirm value function
///
/// This function is used for generating the confirm values for the LE secure connections process,
/// however it is used differently depending on the type of security model.
///
/// # Inputs
/// The inputs u, v, x, and z depend on the type of model used for generating a secure connection.
/// The inputs of `f4` are a combination of *PKax*, *PKbx*, *Na(i)*, *Nb(i)*, ra, rb, rai, and nbi,
/// but not all of these are used for each model. Check the sections for each model to see what
/// values are used for the inputs to `f4`.
///
/// * PKax is the x coordinate of the public key of Device A
/// * PKbx is the x coordinate of the public key of Device B
/// * Na is the nonce from Device A
/// * Nb is the nonce from Device B
/// * Nai is a nonce value from the *i*th round from Device A
/// * Nbi is a nonce value from the *i*th round from Device B
/// * ra is a random value generated by Device A
/// * rb is a random value generated by Device B
/// * rai is generated by setting the most significant bit to 1 and the least significant bit is one
///   arbitrary bit of the passkey for device A. The value of rai can be either 0x80 or 0x81.
/// * rbi (see rai)
///
/// # Models **Numeric Comparison** or **Just Works**
///
/// ## Calculation of *Ca*
/// * u = PKax
/// * v = PKbx
/// * x = Na
/// * z = 0
///
/// ## Calculation of *Cb*
/// * u = PKbx
/// * v = PKax
/// * x = Nb
/// * z = 0
///
/// # Model **Out-Of-Band**
///
/// ## Calculation of *Ca*
/// * u = PKax
/// * v = PKax
/// * x = ra
/// * z = 0
///
/// ## Calculation of *Cb*
/// * u = PKbx
/// * v = PKbx
/// * x = rb
/// * z = 0
///
/// # Model **Passkey Entry**
///
/// ## Calculation of *Cai*
/// * u = PKax
/// * v = PKbx
/// * x = Nai
/// * z = rai
///
/// ## Calculation of *Cbi*
/// * u = PKbx
/// * v = PKax
/// * x = Nbi
/// * z = rbi
pub fn f4(u: [u8; 32], v: [u8; 32], x: u128, z: u8) -> u128 {
    let mut m = [0u8; 65];

    m[..32].copy_from_slice(&u);

    m[32..64].copy_from_slice(&v);

    m[64] = z;

    aes_cmac_generate(x, &m)
}

/// Phase 2 (LE Secure) long term key (LTK) and MacKey function
///
/// # Calculating LTK and MacKey
///
/// To return a LTK (long term key) and a MacKey (message authentication code key), the inputs
/// needs to be mapped as follows:
///
/// * w:  The shared secret Diffie-Hellman key generated during LE Secure Connections pairing phase 2
/// * n1: A randomly generated number sent from the master device to the slave
/// * n2: A randomly generated number sent from the slave device to the master
/// * a1: The device address of the *master* (in little endian order) with the most significant byte
///       of a1 equal to 0x0 if the address is a public address, or equal to 0x1 if the address is a
///       random address.
/// * a2: The device address of the *slave* (in little endian order) with the most significant byte
///       of a2 equal to 0x0 if the address is a public address, or equal to 0x1 if the address is a
///       random address.
///
/// The returned value is ( MacKey , LTK )
pub fn f5(w: [u8; 32], n1: u128, n2: u128, a1: PairingAddress, a2: PairingAddress) -> (u128, u128) {
    const SALT: u128 = 0x6C888391_AAF5A538_60370BDB_5A6083BE;

    let key_t = aes_cmac_generate(SALT, &w);

    // Because of the order in which in the message to the aes_cmac function, the following values
    // need to be in big endian order.
    let key_id = [0x62, 0x74, 0x6c, 0x65];

    let length = [0x01, 0x00];

    let n1_bytes_be = n1.to_be_bytes();

    let n2_bytes_be = n2.to_be_bytes();

    // The range is the 'Counter' values
    let mut keys = (0u8..=1).map(|counter| {
        let mut m = [0u8; 53];

        m[0] = counter;

        m[1..5].copy_from_slice(&key_id);

        m[5..21].copy_from_slice(&n1_bytes_be);

        m[21..37].copy_from_slice(&n2_bytes_be);

        m[37..44].copy_from_slice(&a1.0);

        m[44..51].copy_from_slice(&a2.0);

        m[51..53].copy_from_slice(&length);

        aes_cmac_generate(key_t, &m)
    });

    let mac_key = keys.next().unwrap();

    let ltk = keys.next().unwrap();

    (mac_key, ltk)
}

/// Phase 2 (LE Secure) check value generator function
///
/// This function is used for generating the check values for the LE secure connections process,
/// however it is used differently depending on the type of security model.
///
/// # Inputs
/// The inputs depend on the type of model used for generating a secure connection. The inputs of
/// `f6` are a combination of MacKey, Na, Nb, rb, ra, rb, Na20, Nb20, IOcapA, IOCapB, A, and B
/// but not all of these are used for each model. Check the sections for each model to see what
/// values are used for the inputs to `f6`.
///
/// * MacKey is the MacKey generated from [`f5`]
/// * Na (and Na20) is the random number sent by the master to the slave
/// * Nb (and Nb20) is the random number sent by the slave to the master
/// * IOcapA is the capabilities of the master
/// * IOcapB is the capabilities of the slave
/// * ra is a 6-digit passkey value represented in 128-bits
/// * rb is a 6-digit passkey value represented in 128-bits
/// * A is the device address of the *master* (in little endian order) with the most significant
///     byte of a1 equal to 0x0 if the address is a public address, or equal to 0x1 if the address
///     is a random address
/// * B is the device address of the *slave* (in little endian order) with the most significant byte
///     of a2 equal to 0x0 if the address is a public address, or equal to 0x1 if the address is a
///     random address.
///
/// # Models Numeric Comparison or Just Works
///
/// ## Calculation of *Ea*
/// * w = MacKey
/// * n1 = Na
/// * n2 = Nb
/// * r = 0
/// * io_cap = IOcapA
/// * a1 = A
/// * a2 = B
///
/// ## Calculation of *Eb*
/// * w = MacKey
/// * n1 = Nb
/// * n2 = Na
/// * r = 0
/// * io_cap = IOcapB
/// * a1 = B
/// * a2 = A
///
/// # Model Out-Of-Band
///
/// ## Calculation of *Ea*
/// * w = MacKey
/// * n1 = Na
/// * n2 = Nb
/// * r = rb
/// * io_cap = IOcapA
/// * a1 = A
/// * a2 = B
///
/// ## Calculation of *Eb*
/// * w = MacKey
/// * n1 = Nb
/// * n2 = Na
/// * r = ra
/// * io_cap = IOcapB
/// * a1 = B
/// * a2 = A
///
/// # Model Passkey Entry
///
/// ## Calculation of *Eai*
/// * w = MacKey
/// * n1 = Na20
/// * n2 = Nb20
/// * r = rb
/// * io_cap = IOcapA
/// * a1 = A
/// * a2 = B
///
/// ## Caluclation of *Ebi*
/// * w = MacKey
/// * n1 = Nb20
/// * n2 = Na20
/// * r = ra
/// * io_cap = IOcapB
/// * a1 = B
/// * a2 = A
pub fn f6(w: u128, n1: u128, n2: u128, r: u128, io_cap: [u8; 3], a1: PairingAddress, a2: PairingAddress) -> u128 {
    let mut m = [0u8; 65];

    m[0..16].copy_from_slice(&n1.to_be_bytes());
    m[16..32].copy_from_slice(&n2.to_be_bytes());
    m[32..48].copy_from_slice(&r.to_be_bytes());
    m[48..51].copy_from_slice(&io_cap);
    m[51..58].copy_from_slice(&a1.0);
    m[58..65].copy_from_slice(&a2.0);

    aes_cmac_generate(w, &m)
}

/// Phase 2 (LE Secure) 6-digit numeric comparison number generator function
///
/// Generating the numeric comparison value is performed by mapping the inputs as follows:
/// * u : PKax - the x-coordinate of the public key PKa of device A
/// * v : PKbx - the x-coordinate of the public key PKb of device B
/// * x : Na - the nonce from device A
/// * y : Nb - the nonce from device B
///
/// The six least significant *digits* of the return of `g2` is the generated numeric verification
/// value
///
/// #
/// # Inputs
/// * g2 and v must be in little endian order
pub fn g2(u: [u8; 32], v: [u8; 32], x: u128, y: u128) -> u32 {
    let mut m = [0u8; 80];

    m[0..32].copy_from_slice(&u);
    m[32..64].copy_from_slice(&v);
    m[64..80].copy_from_slice(&y.to_be_bytes());

    aes_cmac_generate(x, &m) as u32
}

/// A structure used to create the address structures used in pairing function [`f5`] and [`f6`]
#[derive(Clone, Debug)]
pub struct PairingAddress([u8; 7]);

impl PairingAddress {
    pub fn new(addr: &crate::BluetoothDeviceAddress, is_random_address: bool) -> Self {
        let init_byte: u8 = if is_random_address { 1 } else { 0 };

        let mut p_addr = [0, 0, 0, 0, 0, 0, init_byte];

        p_addr[..6].copy_from_slice(addr);

        // Reverse to put the address information into the correct byte order
        p_addr.reverse();

        PairingAddress(p_addr)
    }
}

/// Tests
///
/// The much of the tests data can be retrieved from the end of the Security Manager specification,
/// but some of the tests data is unique. All the data (if the applicable function is implemented)
/// should be used here for testing.
#[cfg(test)]
mod tests {

    use super::*;
    use alloc::format;
    use alloc::string::String;
    use alloc::vec::Vec;

    /// This is handy for converting the byte data in the Bluetooth Specification into tests data
    ///
    /// spec_data is the concatenation of the data as shown. Whitespace doesn't matter.
    ///
    /// ## Example
    /// Continuous data for 'M' shown in the bluetooth specification
    ///  M0             6bc1bee2 2e409f96 e93d7e11 7393172a
    ///  M1             ae2d8a57 1e03ac9c 9eb76fac 45af8e51
    ///  M2             30c81c46 a35ce411
    /// Would translate to
    ///  spec_data      "6bc1bee2 2e409f96 e93d7e11 7393172a ae2d8a57 1e03ac9c 9eb76fac 45af8e51 30c81c46 a35ce411"
    fn parse_spec_test_data(spec_data: &str) -> Vec<u8> {
        let mut m = true;

        let mut m_mode = |&c: &char| {
            if c.is_whitespace() {
                m = true // reset m
            } else if c.is_ascii_uppercase() || !c.is_ascii_hexdigit() {
                m = false // start filtering characters
            }

            m
        };

        spec_data
            .chars()
            .filter(|c| m_mode(c))
            .filter(|&c| !c.is_whitespace())
            .enumerate()
            .fold(String::new(), |mut msg, (i, c)| {
                match i & 1 {
                    0 => msg.push_str(&format!("{}", c)),
                    _ => msg.push_str(&format!("{} ", c)),
                }
                msg
            })
            .trim()
            .split(' ')
            .map(|str_byte| <u8>::from_str_radix(str_byte, 16).unwrap())
            .collect::<Vec<u8>>()
    }

    #[test]
    fn c1_test() {
        let k = 0;
        let r = 0x5783D52156AD6F0E6388274EC6702EE0;
        let pres = 0x05000800000302;
        let preq = 0x07071000000101;
        let iat = true;
        let rat = false;
        let ia = 0xA1A2A3A4A5A6;
        let ra = 0xB1B2B3B4B5B6;

        assert_eq!(0x05000800000302070710000001010001, c1_p1(pres, preq, iat, rat));

        assert_eq!(0x00000000A1A2A3A4A5A6B1B2B3B4B5B6, c1_p2(ia, ra));

        assert_eq!(
            0x1e1e3fef878988ead2a74dc5bef13b86u128,
            c1(k, r, pres, preq, iat, ia, rat, ra)
        );
    }

    #[test]
    fn s1_test() {
        let k = 0;
        let r1 = 0x000F0E0D0C0B0A091122334455667788;
        let r2 = 0x010203040506070899AABBCCDDEEFF00;

        assert_eq!(0x9a1fe1f0e8b0f49b5b4216ae796da062, s1(k, r1, r2));
    }

    /// Data is from section D.2 (Bluetooth Spec. v5.0 | Vol 3, Part H, Appendix D)
    #[test]
    fn f4_test() {
        let mut u = [0u8; 32];

        u.copy_from_slice(&parse_spec_test_data(
            "
            U              20b003d2 f297be2c 5e2c83a7 e9f9a5b9
                           eff49111 acf4fddb cc030148 0e359de6
        ",
        ));

        let mut v = [0u8; 32];

        v.copy_from_slice(&parse_spec_test_data(
            "
            V              55188b3d 32f6bb9a 900afcfb eed4e72a
                           59cb9ac2 f19d7cfb 6b4fdd49 f47fc5fd
        ",
        ));

        let x = 0xd5cb8454_d177733e_ffffb2ec_712baeab;

        let z = 0;

        assert_eq!(f4(u, v, x, z), 0xf2c916f1_07a9bd1c_f1eda1be_a974872d);
    }

    /// Data is from section D.3 (Bluetooth Spec. v5.0 | Vol 3, Part H, Appendix D)
    #[test]
    fn f5_test() {
        let mut dh_key = [0u8; 32];

        dh_key.copy_from_slice(&parse_spec_test_data(
            "
            DHKey(W)       ec0234a3 57c8ad05 341010a6 0a397d9b
                           99796b13 b4f866f1 868d34f3 73bfa698
        ",
        ));

        let n1 = 0xd5cb8454_d177733e_ffffb2ec_712baeab;

        let n2 = 0xa6e8e7cc_25a75f6e_216583f7_ff3dc4cf;

        let mut a1_raw = [0u8; 7];

        a1_raw.copy_from_slice(&parse_spec_test_data("A1             00561237 37bfce"));

        let mut a2_raw = [0u8; 7];

        a2_raw.copy_from_slice(&parse_spec_test_data("A2             00a71370 2dcfc1"));

        let a1 = PairingAddress(a1_raw);

        let a2 = PairingAddress(a2_raw);

        let mac_key = 0x2965f176_a1084a02_fd3f6a20_ce636e20;

        let ltk = 0x69867911_69d7cd23_980522b5_94750a38;

        let rslt = f5(dh_key, n1, n2, a1, a2);

        assert_eq!(
            rslt,
            (mac_key, ltk),
            "\n left in hex: `{:x?}`\nright in hex : `{:x?}`",
            rslt,
            (mac_key, ltk)
        );
    }

    #[test]
    fn f6_test() {
        let n1 = 0xd5cb8454_d177733e_ffffb2ec_712baeab;

        let n2 = 0xa6e8e7cc_25a75f6e_216583f7_ff3dc4cf;

        let mac_key = 0x2965f176_a1084a02_fd3f6a20_ce636e20;

        let r = 0x12a3343b_b453bb54_08da42d2_0c2d0fc8;

        let mut io_cap = [0u8; 3];

        io_cap.copy_from_slice(&parse_spec_test_data("IOcap          010102"));

        let mut a1_raw = [0u8; 7];

        a1_raw.copy_from_slice(&parse_spec_test_data("A1             00561237 37bfce"));

        let mut a2_raw = [0u8; 7];

        a2_raw.copy_from_slice(&parse_spec_test_data("A2             00a71370 2dcfc1"));

        let a1 = PairingAddress(a1_raw);

        let a2 = PairingAddress(a2_raw);

        assert_eq!(
            0xe3c47398_9cd0e8c5_d26c0b09_da958f61,
            f6(mac_key, n1, n2, r, io_cap, a1, a2)
        );
    }

    #[test]
    fn g2_test() {
        let mut u = [0u8; 32];

        u.copy_from_slice(&parse_spec_test_data(
            "\
            U              20b003d2 f297be2c 5e2c83a7 e9f9a5b9               \
                           eff49111 acf4fddb cc030148 0e359de6",
        ));

        let mut v = [0u8; 32];

        v.copy_from_slice(&parse_spec_test_data(
            "\
            V              55188b3d 32f6bb9a 900afcfb eed4e72a               \
                           59cb9ac2 f19d7cfb 6b4fdd49 f47fc5fd",
        ));

        let x = 0xd5cb8454_d177733e_ffffb2ec_712baeab;

        let y = 0xa6e8e7cc_25a75f6e_216583f7_ff3dc4cf;

        assert_eq!(0x2f9ed5ba, g2(u, v, x, y));
    }

    #[test]
    fn try_from_icd_ec_dh_test() {
        use super::super::CommandData;

        let (pri_key, _) = ecc_gen();

        // This is the x and y of the public key specified in the Bluetooth Specification v5.0 | Vol
        // 3, Part H, Section 2.3.5.6.1

        let mut raw_peer_key = [
            0x20, 0xb0, 0x03, 0xd2, 0xf2, 0x97, 0xbe, 0x2c, 0x5e, 0x2c, 0x83, 0xa7, 0xe9, 0xf9, 0xa5, 0xb9, 0xef, 0xf4,
            0x91, 0x11, 0xac, 0xf4, 0xfd, 0xdb, 0xcc, 0x03, 0x01, 0x48, 0x0e, 0x35, 0x9d, 0xe6, 0xdc, 0x80, 0x9c, 0x49,
            0x65, 0x2a, 0xeb, 0x6d, 0x63, 0x32, 0x9a, 0xbf, 0x5a, 0x52, 0x15, 0x5c, 0x76, 0x63, 0x45, 0xc2, 0x8f, 0xed,
            0x30, 0x24, 0x74, 0x1c, 0x8e, 0xd0, 0x15, 0x89, 0xd2, 0x8b,
        ];

        // Matching the Peer Key to the little endian format as specified in the key exchange PDU
        raw_peer_key[..32].reverse();
        raw_peer_key[32..].reverse();

        let peer_key = PubKey::try_from_command_format(&raw_peer_key).expect("Failed to make PeerKey");

        let _secret = ecdh(pri_key, &peer_key);
    }
}
