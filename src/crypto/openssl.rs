use crate::ctap2::crypto::SignatureAlgorithm;
use crate::{errors::AuthenticatorError, Result};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcPoint};
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use serde_bytes::ByteBuf;

impl From<ErrorStack> for AuthenticatorError {
    fn from(_: ErrorStack) -> Self {
        AuthenticatorError::CryptoError
    }
}

fn to_openssl_name(curve: SignatureAlgorithm) -> Nid {
    match curve {
        SignatureAlgorithm::PS256 => Nid::X9_62_PRIME256V1,
        SignatureAlgorithm::ES384 => Nid::SECP384R1,
        // SignatureAlgorithm::X25519 => "x25519",
        _ => unimplemented!(),
    }
}

fn affine_coordinates(curve: SignatureAlgorithm, bytes: &[u8]) -> Result<(ByteBuf, ByteBuf)> {
    let name = to_openssl_name(curve);
    let group = EcGroup::from_curve_name(name)?;

    let mut ctx = BigNumContext::new().unwrap();
    let point = EcPoint::from_bytes(&group, bytes, &mut ctx).unwrap();

    let mut x = BigNum::new()?;
    let mut y = BigNum::new()?;

    point.affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)?;
    //point.affine_coordinates_gf2m(&group, &mut x, &mut y, &mut ctx)?;

    Ok((ByteBuf::from(x.to_vec()), ByteBuf::from(y.to_vec())))
}
