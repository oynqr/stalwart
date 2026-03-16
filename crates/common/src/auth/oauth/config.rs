/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use aws_lc_rs::{
    encoding::{AsDer, EcPrivateKeyRfc5915Der, Pkcs8V1Der},
    signature::{self, KeyPair},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{
    Algorithm,
    EncodingKey,
    jwk::{
        AlgorithmParameters, CommonParameters, EllipticCurve, EllipticCurveKeyParameters,
        EllipticCurveKeyType, Jwk, JwkSet, KeyAlgorithm, OctetKeyParameters, OctetKeyType,
        PublicKeyUse, RSAKeyParameters, RSAKeyType,
    },
};
use rsa::{RsaPublicKey, pkcs1::DecodeRsaPublicKey, traits::PublicKeyParts};
use store::rand::{Rng, distr::Alphanumeric, rng};
use utils::config::Config;

use crate::{
    config::{build_ecdsa_pem, build_rsa_keypair},
    manager::webadmin::Resource,
};

#[derive(Clone)]
pub struct OAuthConfig {
    pub oauth_key: String,
    pub oauth_expiry_user_code: u64,
    pub oauth_expiry_auth_code: u64,
    pub oauth_expiry_token: u64,
    pub oauth_expiry_refresh_token: u64,
    pub oauth_expiry_refresh_token_renew: u64,
    pub oauth_max_auth_attempts: u32,

    pub allow_anonymous_client_registration: bool,
    pub require_client_authentication: bool,

    pub oidc_expiry_id_token: u64,
    pub oidc_signing_secret: EncodingKey,
    pub oidc_signature_algorithm: Algorithm,
    pub oidc_jwks: Resource<Vec<u8>>,
}

impl OAuthConfig {
    pub fn parse(config: &mut Config) -> Self {
        let oidc_signature_algorithm = match config.value("oauth.oidc.signature-algorithm") {
            Some(alg) => match alg.to_uppercase().as_str() {
                "HS256" => Algorithm::HS256,
                "HS384" => Algorithm::HS384,
                "HS512" => Algorithm::HS512,

                "RS256" => Algorithm::RS256,
                "RS384" => Algorithm::RS384,
                "RS512" => Algorithm::RS512,

                "ES256" => Algorithm::ES256,
                "ES384" => Algorithm::ES384,

                "PS256" => Algorithm::PS256,
                "PS384" => Algorithm::PS384,
                "PS512" => Algorithm::PS512,
                _ => {
                    config.new_parse_error(
                        "oauth.oidc.signature-algorithm",
                        format!("Invalid OIDC signature algorithm: {}", alg),
                    );
                    Algorithm::HS256
                }
            },
            None => Algorithm::HS256,
        };

        let rand_key = rng()
            .sample_iter(Alphanumeric)
            .take(64)
            .map(char::from)
            .collect::<String>()
            .into_bytes();

        let (oidc_signing_secret, algorithm) = match oidc_signature_algorithm {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                let key = config
                    .value("oauth.oidc.signature-key")
                    .map(|s| s.to_string().into_bytes())
                    .unwrap_or_else(|| rand_key.clone());

                (
                    EncodingKey::from_secret(&key),
                    AlgorithmParameters::OctetKey(OctetKeyParameters {
                        key_type: OctetKeyType::Octet,
                        value: URL_SAFE_NO_PAD.encode(&key),
                    }),
                )
            }
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512 => parse_rsa_key(config).unwrap_or_else(|| {
                (
                    EncodingKey::from_secret(&rand_key),
                    AlgorithmParameters::OctetKey(OctetKeyParameters {
                        key_type: OctetKeyType::Octet,
                        value: URL_SAFE_NO_PAD.encode(&rand_key),
                    }),
                )
            }),
            Algorithm::ES256 | Algorithm::ES384 => {
                parse_ecdsa_key(config, oidc_signature_algorithm).unwrap_or_else(|| {
                    (
                        EncodingKey::from_secret(&rand_key),
                        AlgorithmParameters::OctetKey(OctetKeyParameters {
                            key_type: OctetKeyType::Octet,
                            value: URL_SAFE_NO_PAD.encode(&rand_key),
                        }),
                    )
                })
            }
            // EdDSA and any future variants: fall back to HMAC secret
            _ => (
                EncodingKey::from_secret(&rand_key),
                AlgorithmParameters::OctetKey(OctetKeyParameters {
                    key_type: OctetKeyType::Octet,
                    value: URL_SAFE_NO_PAD.encode(&rand_key),
                }),
            ),
        };

        let key_algorithm = match oidc_signature_algorithm {
            Algorithm::HS256 => KeyAlgorithm::HS256,
            Algorithm::HS384 => KeyAlgorithm::HS384,
            Algorithm::HS512 => KeyAlgorithm::HS512,
            Algorithm::RS256 => KeyAlgorithm::RS256,
            Algorithm::RS384 => KeyAlgorithm::RS384,
            Algorithm::RS512 => KeyAlgorithm::RS512,
            Algorithm::ES256 => KeyAlgorithm::ES256,
            Algorithm::ES384 => KeyAlgorithm::ES384,
            Algorithm::PS256 => KeyAlgorithm::PS256,
            Algorithm::PS384 => KeyAlgorithm::PS384,
            Algorithm::PS512 => KeyAlgorithm::PS512,
            Algorithm::EdDSA => KeyAlgorithm::EdDSA,
        };

        let oidc_jwks = Resource {
            content_type: "application/json".into(),
            contents: serde_json::to_string(&JwkSet {
                keys: vec![Jwk {
                    common: CommonParameters {
                        public_key_use: PublicKeyUse::Signature.into(),
                        key_algorithm: key_algorithm.into(),
                        key_id: "default".to_string().into(),
                        ..Default::default()
                    },
                    algorithm,
                }],
            })
            .unwrap_or_default()
            .into_bytes(),
        };

        OAuthConfig {
            oauth_key: config
                .value("oauth.key")
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    rng()
                        .sample_iter(Alphanumeric)
                        .take(64)
                        .map(char::from)
                        .collect::<String>()
                }),
            oauth_expiry_user_code: config
                .property_or_default::<Duration>("oauth.expiry.user-code", "30m")
                .unwrap_or_else(|| Duration::from_secs(30 * 60))
                .as_secs(),
            oauth_expiry_auth_code: config
                .property_or_default::<Duration>("oauth.expiry.auth-code", "10m")
                .unwrap_or_else(|| Duration::from_secs(10 * 60))
                .as_secs(),
            oauth_expiry_token: config
                .property_or_default::<Duration>("oauth.expiry.token", "1h")
                .unwrap_or_else(|| Duration::from_secs(60 * 60))
                .as_secs(),
            oauth_expiry_refresh_token: config
                .property_or_default::<Duration>("oauth.expiry.refresh-token", "30d")
                .unwrap_or_else(|| Duration::from_secs(30 * 24 * 60 * 60))
                .as_secs(),
            oauth_expiry_refresh_token_renew: config
                .property_or_default::<Duration>("oauth.expiry.refresh-token-renew", "4d")
                .unwrap_or_else(|| Duration::from_secs(4 * 24 * 60 * 60))
                .as_secs(),
            oauth_max_auth_attempts: config
                .property_or_default("oauth.auth.max-attempts", "3")
                .unwrap_or(10),
            oidc_expiry_id_token: config
                .property_or_default::<Duration>("oauth.oidc.expiry.id-token", "15m")
                .unwrap_or_else(|| Duration::from_secs(15 * 60))
                .as_secs(),
            allow_anonymous_client_registration: config
                .property_or_default("oauth.client-registration.anonymous", "false")
                .unwrap_or(false),
            require_client_authentication: config
                .property_or_default("oauth.client-registration.require", "false")
                .unwrap_or(true),
            oidc_signing_secret,
            oidc_signature_algorithm,
            oidc_jwks,
        }
    }
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            oauth_key: Default::default(),
            oauth_expiry_user_code: Default::default(),
            oauth_expiry_auth_code: Default::default(),
            oauth_expiry_token: Default::default(),
            oauth_expiry_refresh_token: Default::default(),
            oauth_expiry_refresh_token_renew: Default::default(),
            oauth_max_auth_attempts: Default::default(),
            oidc_expiry_id_token: Default::default(),
            allow_anonymous_client_registration: Default::default(),
            require_client_authentication: Default::default(),
            oidc_signing_secret: EncodingKey::from_secret(b"secret"),
            oidc_signature_algorithm: Algorithm::HS256,
            oidc_jwks: Resource {
                content_type: "application/json".into(),
                contents: serde_json::to_string(&JwkSet { keys: vec![] })
                    .unwrap_or_default()
                    .into_bytes(),
            },
        }
    }
}

fn parse_rsa_key(config: &mut Config) -> Option<(EncodingKey, AlgorithmParameters)> {
    let rsa_key_pair = match build_rsa_keypair(config.value_require("oauth.oidc.signature-key")?) {
        Ok(key) => key,
        Err(err) => {
            config.new_build_error(
                "oauth.oidc.signature-key",
                format!("Failed to build RSA key: {}", err),
            );
            return None;
        }
    };

    let rsa_public_key = match RsaPublicKey::from_pkcs1_der(rsa_key_pair.public_key().as_ref()) {
        Ok(key) => key,
        Err(err) => {
            config.new_build_error(
                "oauth.oidc.signature-key",
                format!("Failed to obtain RSA public key: {}", err),
            );
            return None;
        }
    };

    let rsa_key_params = RSAKeyParameters {
        key_type: RSAKeyType::RSA,
        n: URL_SAFE_NO_PAD.encode(rsa_public_key.n().to_bytes_be()),
        e: URL_SAFE_NO_PAD.encode(rsa_public_key.e().to_bytes_be()),
        ..Default::default()
    };

    // Serialize the RsaKeyPair to PKCS#8 DER for jsonwebtoken's EncodingKey.
    // AsDer::<Pkcs8V1Der>::as_der is fallible; from_rsa_der is infallible.
    let pkcs8_der = match AsDer::<Pkcs8V1Der>::as_der(&rsa_key_pair) {
        Ok(der) => der,
        Err(err) => {
            config.new_build_error(
                "oauth.oidc.signature-key",
                format!("Failed to serialize RSA key to DER: {}", err),
            );
            return None;
        }
    };
    let encoding_key = EncodingKey::from_rsa_der(pkcs8_der.as_ref());

    (encoding_key, AlgorithmParameters::RSA(rsa_key_params)).into()
}

fn parse_ecdsa_key(
    config: &mut Config,
    oidc_signature_algorithm: Algorithm,
) -> Option<(EncodingKey, AlgorithmParameters)> {
    let (alg, curve) = match oidc_signature_algorithm {
        Algorithm::ES256 => (
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            EllipticCurve::P256,
        ),
        Algorithm::ES384 => (
            &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            EllipticCurve::P384,
        ),
        _ => unreachable!(),
    };

    let ecdsa_key_pair =
        match build_ecdsa_pem(alg, config.value_require("oauth.oidc.signature-key")?) {
            Ok(key) => key,
            Err(err) => {
                config.new_build_error(
                    "oauth.oidc.signature-key",
                    format!("Failed to build ECDSA key: {}", err),
                );
                return None;
            }
        };

    let ecdsa_public_key = ecdsa_key_pair.public_key().as_ref();

    let (x, y) = match oidc_signature_algorithm {
        Algorithm::ES256 => {
            let points = match p256::EncodedPoint::from_bytes(ecdsa_public_key) {
                Ok(points) => points,
                Err(err) => {
                    config.new_build_error(
                        "oauth.oidc.signature-key",
                        format!("Failed to parse ECDSA key: {}", err),
                    );
                    return None;
                }
            };

            (
                URL_SAFE_NO_PAD.encode(points.x().map(|x| x.as_slice()).unwrap_or_default()),
                URL_SAFE_NO_PAD.encode(points.y().map(|y| y.as_slice()).unwrap_or_default()),
            )
        }
        Algorithm::ES384 => {
            let points = match p384::EncodedPoint::from_bytes(ecdsa_public_key) {
                Ok(points) => points,
                Err(err) => {
                    config.new_build_error(
                        "oauth.oidc.signature-key",
                        format!("Failed to parse ECDSA key: {}", err),
                    );
                    return None;
                }
            };

            (
                URL_SAFE_NO_PAD.encode(points.x().map(|x| x.as_slice()).unwrap_or_default()),
                URL_SAFE_NO_PAD.encode(points.y().map(|y| y.as_slice()).unwrap_or_default()),
            )
        }
        _ => unreachable!(),
    };

    let ecdsa_key_params = EllipticCurveKeyParameters {
        key_type: EllipticCurveKeyType::EC,
        curve,
        x,
        y,
    };

    // EcdsaKeyPair does not implement AsDer<Pkcs8V1Der>; instead, access the
    // private key component and serialize it as RFC 5915 DER, which is what
    // jsonwebtoken's from_ec_der accepts.
    let ec_der = match AsDer::<EcPrivateKeyRfc5915Der>::as_der(&ecdsa_key_pair.private_key()) {
        Ok(der) => der,
        Err(err) => {
            config.new_build_error(
                "oauth.oidc.signature-key",
                format!("Failed to serialize ECDSA key to DER: {}", err),
            );
            return None;
        }
    };
    let encoding_key = EncodingKey::from_ec_der(ec_der.as_ref());

    (
        encoding_key,
        AlgorithmParameters::EllipticCurve(ecdsa_key_params),
    )
        .into()
}