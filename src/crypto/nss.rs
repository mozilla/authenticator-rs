use super::{COSEAlgorithm, COSEEC2Key, COSEKey, COSEKeyType, ECDHSecret, ECDSACurve};
use nss_gk_api::p11::{
    PK11Origin, PK11_CreateContextBySymKey, PK11_Decrypt, PK11_DigestFinal, PK11_DigestOp,
    PK11_Encrypt, PK11_ExtractKeyValue, PK11_GenerateKeyPairWithOpFlags, PK11_GetInternalSlot,
    PK11_GetKeyData, PK11_ImportDataKey, PK11_PubDeriveWithKDF, PK11_ReadRawAttribute, PrivateKey,
    PublicKey, SECOID_FindOIDByTag, SECOidTag, AES_BLOCK_SIZE, CKA_EC_POINT, CKA_ENCRYPT, CKA_SIGN,
    CKD_SHA256_KDF, CKF_DERIVE, CKM_AES_CBC, CKM_ECDH1_DERIVE, CKM_EC_KEY_PAIR_GEN,
    CKM_SHA256_HMAC, CKM_SHA512_HMAC, CKO_PUBLIC_KEY, CK_FLAGS, CK_MECHANISM_TYPE,
    PK11_ATTR_INSENSITIVE, PK11_ATTR_PUBLIC, PK11_ATTR_SESSION, SEC_ASN1_OBJECT_ID, SHA256_LENGTH,
};
use nss_gk_api::{Error as NSSError, IntoResult, SECItem, SECItemBorrowed, SECItemMut, PR_FALSE};
use serde::Serialize;
use serde_bytes::ByteBuf;
use std::convert::{TryFrom, TryInto};
use std::ffi::c_void;
use std::num::TryFromIntError;
use std::os::raw::{c_uchar, c_uint};
use std::ptr;

/// Errors that can be returned from COSE functions.
#[derive(Clone, Debug, Serialize)]
pub enum BackendError {
    NSSError(String),
    TryFromError,
    UnsupportedAlgorithm(COSEAlgorithm),
    UnsupportedCurve(ECDSACurve),
    UnsupportedKeyType,
}

impl From<NSSError> for BackendError {
    fn from(e: NSSError) -> Self {
        BackendError::NSSError(format!("{}", e))
    }
}

impl From<TryFromIntError> for BackendError {
    fn from(_: TryFromIntError) -> Self {
        BackendError::TryFromError
    }
}

pub type Result<T> = std::result::Result<T, BackendError>;

/// A key agreement algorithm.
#[derive(PartialEq)]
pub struct Algorithm {
    curve_id: SECOidTag::Type,
}

pub static ECDH_P256: Algorithm = Algorithm {
    curve_id: SECOidTag::SEC_OID_ANSIX962_EC_PRIME256V1,
};

pub static ECDH_P384: Algorithm = Algorithm {
    curve_id: SECOidTag::SEC_OID_SECG_EC_SECP384R1,
};

pub enum Curve {
    P256,
    P384,
}

fn to_nss_alg(curve: COSEAlgorithm) -> Result<&'static Algorithm> {
    match curve {
        // TODO(MS): Are these correct / complete?
        COSEAlgorithm::ES256
        | COSEAlgorithm::PS256
        | COSEAlgorithm::ECDH_ES_HKDF256
        | COSEAlgorithm::ECDH_SS_HKDF256 => Ok(&ECDH_P256),
        COSEAlgorithm::ES384 => Ok(&ECDH_P384),
        x => Err(BackendError::UnsupportedAlgorithm(x)),
    }
}

fn to_nss_curve(curve: ECDSACurve) -> Result<Curve> {
    match curve {
        // TODO(MS): Are these correct / complete?
        ECDSACurve::SECP256R1 => Ok(Curve::P256),
        ECDSACurve::SECP384R1 => Ok(Curve::P256),
        ECDSACurve::SECP521R1 => Ok(Curve::P384),
        x => Err(BackendError::UnsupportedCurve(x)),
    }
}

/* From CTAP2.1 spec:

initialize()

    This is run by the platform when starting a series of transactions with a specific authenticator.
encapsulate(peerCoseKey) → (coseKey, sharedSecret) | error

    Generates an encapsulation for the authenticator’s public key and returns the message to transmit and the shared secret.
encrypt(key, demPlaintext) → ciphertext

    Encrypts a plaintext to produce a ciphertext, which may be longer than the plaintext. The plaintext is restricted to being a multiple of the AES block size (16 bytes) in length.
decrypt(key, ciphertext) → plaintext | error

    Decrypts a ciphertext and returns the plaintext.
authenticate(key, message) → signature

    Computes a MAC of the given message.
*/

// TODO(MS): Maybe remove ByteBuf and return Vec<u8>'s instead for a cleaner interface
pub(crate) fn serialize_key(_curve: ECDSACurve, key: &[u8]) -> Result<(ByteBuf, ByteBuf)> {
    // TODO(MS): I actually have NO idea how to do this with NSS
    let length = key[1..].len() / 2;
    let chunks: Vec<_> = key[1..].chunks_exact(length).collect();
    Ok((
        ByteBuf::from(chunks[0].to_vec()),
        ByteBuf::from(chunks[1].to_vec()),
    ))
}

pub(crate) fn parse_key(curve: ECDSACurve, x: &[u8], y: &[u8]) -> Result<Vec<u8>> {
    todo!()
    /*
    let nss_name = to_nss_curve(curve)?;
    // Note:: NSSPublicKey does not provide the from_coordinates-function, so we have to go via EcKey
    //        and fake a private key.
    let key =
        EcKey::from_coordinates(nss_name, &[], x, y).map_err(|e| NSSError::from(e))?;

    Ok(key.public_key().to_vec())
    */
}

/// This is run by the platform when starting a series of transactions with a specific authenticator.
// pub(crate) fn initialize() {
//     unimplemented!()
// }

fn create_ec_params(algorithm: &Algorithm) -> Result<Vec<u8>> {
    // The following code is adapted from application-services/components/support/rc_crypto/nss/src/ec.rs and
    // https://searchfox.org/mozilla-central/rev/ec489aa170b6486891cf3625717d6fa12bcd11c1/dom/crypto/WebCryptoCommon.h#299
    let oid_data = unsafe { SECOID_FindOIDByTag(algorithm.curve_id as u32).into_result() }?;
    // Set parameters
    let oid_data_len = unsafe { (*oid_data).oid.len };
    let mut buf = vec![0u8; usize::try_from(oid_data_len)? + 2];
    buf[0] = c_uchar::try_from(SEC_ASN1_OBJECT_ID)?;
    buf[1] = c_uchar::try_from(oid_data_len)?;
    let oid_data_data =
        unsafe { std::slice::from_raw_parts((*oid_data).oid.data, usize::try_from(oid_data_len)?) };
    buf[2..].copy_from_slice(oid_data_data);
    Ok(buf)
}

/// Generates an encapsulation for the authenticator’s public key and returns the message
/// to transmit and the shared secret.
///
/// `key` is the authenticator's (peer's) public key.
pub(crate) fn encapsulate(key: &COSEKey) -> Result<ECDHSecret> {
    // TODO: ensure_nss_initialized();
    let slot = unsafe { PK11_GetInternalSlot().into_result() }?;
    if let COSEKeyType::EC2(ec2key) = &key.key {
        // Generate an ephmeral keypair to do ECDH with the authenticator.
        // This is "platformKeyAgreementKey".
        let alg = to_nss_alg(key.alg)?;
        let params = create_ec_params(alg)?;
        let mut public_ptr = ptr::null_mut();
        let private = unsafe {
            // Type of `param` argument depends on mechanism. For EC keygen it is
            // `SECKEYECParams *` which is a typedef for `SECItem *`.
            PK11_GenerateKeyPairWithOpFlags(
                *slot,
                CK_MECHANISM_TYPE::from(CKM_EC_KEY_PAIR_GEN),
                SECItemBorrowed::wrap(&params).as_mut() as *mut SECItem as *mut c_void,
                &mut public_ptr,
                PK11_ATTR_SESSION | PK11_ATTR_INSENSITIVE | PK11_ATTR_PUBLIC,
                CK_FLAGS::from(CKF_DERIVE),
                CK_FLAGS::from(CKF_DERIVE),
                ptr::null_mut(),
            )
            .into_result()?
        };
        // The only error that can be returned here is a null pointer, which
        // shouldn't happen if the call above succeeded, but check anyways.
        let public = unsafe { PublicKey::from_ptr(public_ptr) }?;
        encapsulate_helper(ec2key, key.alg, public, private)
    } else {
        Err(BackendError::UnsupportedKeyType)
    }
}

// `key`: The authenticator's public key.
// `public_key`: Our ephemeral public key.
// `private_key`: Our ephemeral private key.
fn encapsulate_helper(
    key: &COSEEC2Key,
    alg: COSEAlgorithm,
    public_key: PublicKey,
    private_key: PrivateKey,
) -> Result<ECDHSecret> {
    let mut public_key_point = SECItemMut::make_empty();
    unsafe {
        PK11_ReadRawAttribute(
            CKO_PUBLIC_KEY,
            (*public_key).cast(),
            CKA_EC_POINT.into(),
            public_key_point.as_mut(),
        );
    }
    let (x, y) = serialize_key(key.curve, public_key_point.as_slice())?;

    let my_public_key = COSEKey {
        alg,
        key: COSEKeyType::EC2(COSEEC2Key {
            curve: key.curve.clone(),
            x: x.to_vec(),
            y: y.to_vec(),
        }),
    };

    // CKM_SHA512_HMAC and CKA_SIGN are key type and usage attributes of the
    // derived symmetric key and don't matter because we ignore them anyway.
    let sym_key = unsafe {
        PK11_PubDeriveWithKDF(
            *private_key,
            *public_key,
            PR_FALSE as i32,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CKM_ECDH1_DERIVE.into(),
            CKM_SHA512_HMAC.into(),
            CKA_SIGN.into(),
            0,
            CKD_SHA256_KDF.into(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
        .into_result()?
    };

    unsafe { PK11_ExtractKeyValue(*sym_key).into_result()? }

    // PK11_GetKeyData returns a `SECItem *`. Both the SECItem structure and the
    // buffer it refers to are owned by the SymKey. We don't need to free them.
    let shared_secret = unsafe { (*PK11_GetKeyData(*sym_key)).as_slice().to_owned() };

    Ok(ECDHSecret {
        remote: COSEKey {
            alg,
            key: COSEKeyType::EC2(key.clone()),
        },
        my: my_public_key,
        shared_secret,
    })
}

/*
#[cfg(test)]
pub(crate) fn test_encapsulate(
    key: &COSEEC2Key,
    alg: COSEAlgorithm,
    my_pub_key: &[u8],
    my_priv_key: &[u8],
) -> Result<ECDHSecret> {
    let curve = to_nss_curve(key.curve)?;
    let ec_key = EcKey::new(curve, my_priv_key, my_pub_key);
    let private_key = PrivateKey::import(&ec_key)?;
    encapsulate_helper(
        key,
        alg,
        my_pub_key,
        private_key._tests_only_dangerously_convert_to_ephemeral(),
    )
}
*/

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Operation {
    Encrypt,
    Decrypt,
}

/// Encrypts a plaintext to produce a ciphertext, which may be longer than the plaintext.
/// The plaintext is restricted to being a multiple of the AES block size (16 bytes) in length.
pub(crate) fn encrypt(
    key: &[u8],
    plain_text: &[u8], /*PlainText*/
) -> Result<Vec<u8> /*CypherText*/> {
    crypt_helper(key, plain_text, Operation::Encrypt)
}

/// Decrypts a ciphertext and returns the plaintext.
pub(crate) fn decrypt(
    key: &[u8],
    cypher_text: &[u8], /*CypherText*/
) -> Result<Vec<u8> /*PlainText*/> {
    crypt_helper(key, cypher_text, Operation::Decrypt)
}

/// Computes a MAC of the given message.
pub(crate) fn authenticate(token: &[u8], input: &[u8]) -> Result<Vec<u8>> {
    // TODO: ensure_nss_initialized();
    let slot = unsafe { PK11_GetInternalSlot().into_result() }?;
    let sym_key = unsafe {
        PK11_ImportDataKey(
            *slot,
            CKM_SHA256_HMAC.into(),
            PK11Origin::PK11_OriginUnwrap as u32,
            CKA_SIGN.into(),
            SECItemBorrowed::wrap(token).as_mut(),
            ptr::null_mut(),
        )
        .into_result()?
    };
    let param = SECItemBorrowed::make_empty();
    let context = unsafe {
        PK11_CreateContextBySymKey(
            CKM_SHA256_HMAC.into(),
            CKA_SIGN.into(),
            *sym_key,
            param.as_ref(),
        )
        .into_result()?
    };
    unsafe { PK11_DigestOp(*context, input.as_ptr(), input.len().try_into()?).into_result()? };
    let mut digest = vec![0u8; SHA256_LENGTH as usize];
    let mut digest_len = 0u32;
    unsafe {
        PK11_DigestFinal(
            *context,
            digest.as_mut_ptr(),
            &mut digest_len,
            digest.len() as u32,
        )
        .into_result()?
    }
    assert_eq!(digest_len, SHA256_LENGTH);
    Ok(digest)
}

pub fn crypt_helper(key: &[u8], data: &[u8], operation: Operation) -> Result<Vec<u8>> {
    // TODO: ensure_nss_initialized();

    let slot = unsafe { PK11_GetInternalSlot().into_result() }?;
    let mech = CKM_AES_CBC.into();

    let iv = [0u8; 16];

    let mut params = SECItemBorrowed::wrap(&iv);

    // Most of the following code is inspired by the Firefox WebCrypto implementation:
    // https://searchfox.org/mozilla-central/rev/f46e2bf881d522a440b30cbf5cf8d76fc212eaf4/dom/crypto/WebCryptoTask.cpp#566
    // CKA_ENCRYPT always is fine.
    let sym_key = unsafe {
        PK11_ImportDataKey(
            *slot,
            mech,
            PK11Origin::PK11_OriginUnwrap as u32,
            CKA_ENCRYPT.into(),
            SECItemBorrowed::wrap(key).as_mut(),
            ptr::null_mut(),
        )
        .into_result()?
    };

    let result_max_len = data
        .len()
        .checked_add(AES_BLOCK_SIZE as usize)
        .ok_or(BackendError::TryFromError)?;
    let mut out_len: c_uint = 0;
    let mut out = vec![0u8; result_max_len];
    let result_max_len_uint = c_uint::try_from(result_max_len)?;
    let data_len = c_uint::try_from(data.len())?;
    let f = match operation {
        Operation::Decrypt => PK11_Decrypt,
        Operation::Encrypt => PK11_Encrypt,
    };
    unsafe {
        f(
            *sym_key,
            mech,
            params.as_mut() as *mut _,
            out.as_mut_ptr(),
            &mut out_len,
            result_max_len_uint,
            data.as_ptr(),
            data_len,
        )
        .into_result()?
    }
    out.truncate(usize::try_from(out_len)?);
    Ok(out)
}
