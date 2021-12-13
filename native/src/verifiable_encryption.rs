extern crate serde;
extern crate serde_json;

use neon::prelude::*;

use centipede::juggling::{
    proof_system::{Helgamalsegmented, Proof, Witness},
    segmentation::Msegmentation,
};
use curv::elliptic::curves::secp256_k1::Secp256k1Point;
use curv::elliptic::curves::{Point, Scalar};
use curv::BigInt;
use curv::{arithmetic::traits::Converter, elliptic::curves::ECPoint};
use hex;
use secp256k1::constants::{GENERATOR_X, GENERATOR_Y};

use crate::NUM_OF_SEGMENTS;
use crate::SEGMENT_SIZE;

pub fn pad(uncompressed_bytes: &[u8]) -> [u8; 65] {
    let mut padded = [0u8; 65];
    padded[0] = 0x04;
    padded[1..33].copy_from_slice(&uncompressed_bytes[0..32]);
    padded[33..].copy_from_slice(&uncompressed_bytes[32..]);
    return padded;
}

#[allow(non_snake_case)]
pub fn encrypt(mut cx: FunctionContext) -> JsResult<JsString> {
    let expected_args = 2;
    if cx.len() != expected_args {
        return cx.throw_error("Invalid number of arguments");
    }

    let public_key_hex: String = cx.argument::<JsString>(0)?.value();
    let public_key_bytes = hex::decode(&public_key_hex).expect(&format!(
        "failed hex::decode of public_key for encrypt {}",
        &public_key_hex
    ));

    let public_key = Point::from_raw(
        Secp256k1Point::deserialize(&pad(public_key_bytes.as_slice())).expect(&format!(
            "failed deserialization of public_key for encrypt {} bytes len {}",
            &public_key_hex,
            public_key_bytes.as_slice().len()
        )),
    )
    .expect(&format!(
        "failed to create Point from raw public_key {}",
        &public_key_hex
    ));

    let secret_hex: String = cx.argument::<JsString>(1)?.value();
    let secret_bn = BigInt::from_hex(&secret_hex).expect(&format!(
        "could not parse secret_bn from hex {}",
        &secret_hex
    ));
    let secret = Scalar::from_bigint(&secret_bn);

    let GENERATOR_UNCOMRESSED: [u8; 65] = {
        let mut g = [0u8; 65];
        g[0] = 0x04;
        g[1..33].copy_from_slice(&GENERATOR_X);
        g[33..].copy_from_slice(&GENERATOR_Y);
        g
    };

    let G = Point::from_raw(
        Secp256k1Point::deserialize(&GENERATOR_UNCOMRESSED).expect("could not get generator"),
    )
    .expect("could not create generator point from raw");

    let (witness, segments) = Msegmentation::to_encrypted_segments(
        &secret,
        &SEGMENT_SIZE,
        NUM_OF_SEGMENTS,
        &public_key,
        &G,
    );

    Ok(cx.string(serde_json::to_string(&(witness, segments)).unwrap()))
}

#[allow(non_snake_case)]
pub fn decrypt(mut cx: FunctionContext) -> JsResult<JsString> {
    let expected_args = 2;
    if cx.len() != expected_args {
        return cx.throw_error("Invalid number of arguments");
    }

    let private_key_hex: String = cx.argument::<JsString>(0)?.value(); // decryption key
    let private_key_bn = BigInt::from_hex(&private_key_hex).expect(&format!(
        "could not parse private key from hex {}",
        &private_key_hex
    ));
    let private_key = Scalar::from_bigint(&private_key_bn);

    let DE_vec: Helgamalsegmented = serde_json::from_str(&cx.argument::<JsString>(1)?.value())
        .expect("failed deserialization Helgamalsegmented");

    let GENERATOR_UNCOMRESSED: [u8; 65] = {
        let mut g = [0u8; 65];
        g[0] = 0x04;
        g[1..33].copy_from_slice(&GENERATOR_X);
        g[33..].copy_from_slice(&GENERATOR_Y);
        g
    };

    let G = Point::from_raw(
        Secp256k1Point::deserialize(&GENERATOR_UNCOMRESSED).expect("could not get generator"),
    )
    .expect("could not create generator point from raw");

    let secret = Msegmentation::decrypt(&DE_vec, &G, &private_key, &SEGMENT_SIZE)
        .expect("failed decrypting");

    Ok(cx.string(secret.to_bigint().to_hex()))
}

#[allow(non_snake_case)]
pub fn prove(mut cx: FunctionContext) -> JsResult<JsString> {
    let expected_args = 3;
    if cx.len() != expected_args {
        return cx.throw_error("Invalid number of arguments");
    }

    let public_key_hex: String = cx.argument::<JsString>(0)?.value();
    let public_key_bytes = hex::decode(&public_key_hex).expect(&format!(
        "failed hex::decode of public_key for prove {}",
        &public_key_hex
    ));
    let public_key = Point::from_raw(
        Secp256k1Point::deserialize(&pad(public_key_bytes.as_slice())).expect(&format!(
            "failed deserialization of public_key for prove {}",
            &public_key_hex
        )),
    )
    .expect(&format!(
        "could not create point from public_key {}",
        &public_key_hex
    ));

    let segments: Witness = serde_json::from_str(&cx.argument::<JsString>(1)?.value())
        .expect("failed deserialization Witness");

    let encryptions: Helgamalsegmented = serde_json::from_str(&cx.argument::<JsString>(2)?.value())
        .expect("failed deserialization Helgamalsegmented");

    let GENERATOR_UNCOMRESSED: [u8; 65] = {
        let mut g = [0u8; 65];
        g[0] = 0x04;
        g[1..33].copy_from_slice(&GENERATOR_X);
        g[33..].copy_from_slice(&GENERATOR_Y);
        g
    };

    let G = Point::from_raw(
        Secp256k1Point::deserialize(&GENERATOR_UNCOMRESSED).expect("could not get generator"),
    )
    .expect("failed to create generator point from raw");

    let proof = Proof::prove(&segments, &encryptions, &G, &public_key, &SEGMENT_SIZE);

    Ok(cx.string(serde_json::to_string(&proof).unwrap()))
}

#[allow(non_snake_case)]
pub fn verify(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let expected_args = 4;
    if cx.len() != expected_args {
        return cx.throw_error("Invalid number of arguments");
    }

    let proof: Proof = serde_json::from_str(&cx.argument::<JsString>(0)?.value())
        .expect("failed deserialization of Proof");

    let encryption_key_hex: String = cx.argument::<JsString>(1)?.value();
    let encryption_key_bytes = hex::decode(&encryption_key_hex).expect(&format!(
        "failed hex::decode of encryption_key {}",
        &encryption_key_hex
    ));
    let encryption_key = Point::from_raw(
        Secp256k1Point::deserialize(&pad(encryption_key_bytes.as_slice())).expect(&format!(
            "failed deserialization of encryption_key {}",
            &encryption_key_hex
        )),
    )
    .expect(&format!(
        "failed to create point from encryption_key hex {}",
        &encryption_key_hex
    ));

    let public_key_hex: String = cx.argument::<JsString>(2)?.value();
    let public_key_bytes = hex::decode(&public_key_hex).expect(&format!(
        "failed hex::decode of public_key for verify {}",
        &public_key_hex
    ));
    let public_key = Point::from_raw(
        Secp256k1Point::deserialize(&pad(public_key_bytes.as_slice())).expect(&format!(
            "failed deserialization of public_key for verify {}",
            &public_key_hex
        )),
    )
    .expect(&format!(
        "failed to create point from public_key hex for verify {}",
        &public_key_hex
    ));

    let encryptions: Helgamalsegmented = serde_json::from_str(&cx.argument::<JsString>(3)?.value())
        .expect("failed deserialization Helgamalsegmented");

    let GENERATOR_UNCOMRESSED: [u8; 65] = {
        let mut g = [0u8; 65];
        g[0] = 0x04;
        g[1..33].copy_from_slice(&GENERATOR_X);
        g[33..].copy_from_slice(&GENERATOR_Y);
        g
    };

    let G = Point::from_raw(
        Secp256k1Point::deserialize(&GENERATOR_UNCOMRESSED).expect("could not get generator"),
    )
    .expect("could not create generator point from raw");

    match proof.verify(
        &encryptions,
        &G,
        &encryption_key,
        &public_key,
        &SEGMENT_SIZE,
    ) {
        Ok(_) => Ok(cx.boolean(true)),
        Err(_) => Ok(cx.boolean(false)),
    }
}
