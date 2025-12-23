//// ECDSA cryptographic operations for signing and verification.

import gleam/crypto.{type HashAlgorithm, type KeyFormat}

/// ECDSA private key for signing operations.
pub type PrivateKey

/// ECDSA public key for verification operations.
pub type PublicKey

/// ECDSA elliptic curves.
pub type Curve {
  /// NIST P-256 curve (also known as secp256r1 or prime256v1).
  P256
  /// NIST P-384 curve (also known as secp384r1).
  P384
  /// NIST P-521 curve (also known as secp521r1).
  P521
}

/// Generate a new ECDSA key pair for the specified curve.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(#(private_key, public_key)) = ecdsa.generate_key_pair(curve: ecdsa.P256)
/// ```
///
@external(erlang, "gleam_crypto_ecdsa_ffi", "generate_key_pair")
@external(javascript, "../../gleam_crypto_ecdsa_ffi.mjs", "generateKeyPair")
pub fn generate_key_pair(
  curve curve: Curve,
) -> Result(#(PrivateKey, PublicKey), Nil)

/// Import an ECDSA private key from PEM or DER encoded data.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(key) = ecdsa.private_key(pem_data, format: crypto.Pem)
/// ```
///
@external(erlang, "gleam_crypto_ecdsa_ffi", "private_key")
@external(javascript, "../../gleam_crypto_ecdsa_ffi.mjs", "privateKey")
pub fn private_key(
  data: BitArray,
  format format: KeyFormat,
) -> Result(PrivateKey, Nil)

/// Import an ECDSA public key from PEM or DER encoded data.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(key) = ecdsa.public_key(pem_data, format: crypto.Pem)
/// ```
///
@external(erlang, "gleam_crypto_ecdsa_ffi", "public_key")
@external(javascript, "../../gleam_crypto_ecdsa_ffi.mjs", "publicKey")
pub fn public_key(
  data: BitArray,
  format format: KeyFormat,
) -> Result(PublicKey, Nil)

/// Export an ECDSA private key to PEM or DER format.
///
@external(erlang, "gleam_crypto_ecdsa_ffi", "private_key_to_bytes")
@external(javascript, "../../gleam_crypto_ecdsa_ffi.mjs", "privateKeyToBytes")
pub fn private_key_to_bytes(
  key key: PrivateKey,
  format format: KeyFormat,
) -> BitArray

/// Export an ECDSA public key to PEM or DER format.
///
@external(erlang, "gleam_crypto_ecdsa_ffi", "public_key_to_bytes")
@external(javascript, "../../gleam_crypto_ecdsa_ffi.mjs", "publicKeyToBytes")
pub fn public_key_to_bytes(
  key key: PublicKey,
  format format: KeyFormat,
) -> BitArray

/// Extract the public key from an ECDSA private key.
///
@external(erlang, "gleam_crypto_ecdsa_ffi", "public_key_from_private")
@external(javascript, "../../gleam_crypto_ecdsa_ffi.mjs", "publicKeyFromPrivate")
pub fn public_key_from_private(key key: PrivateKey) -> PublicKey

/// Sign a message using an ECDSA private key.
///
/// ## Examples
///
/// ```gleam
/// let signature = ecdsa.sign(
///   key: private_key,
///   message: <<"hello":utf8>>,
///   hash: crypto.Sha256,
/// )
/// ```
///
@external(erlang, "gleam_crypto_ecdsa_ffi", "sign")
@external(javascript, "../../gleam_crypto_ecdsa_ffi.mjs", "sign")
pub fn sign(
  key key: PrivateKey,
  message message: BitArray,
  hash hash: HashAlgorithm,
) -> BitArray

/// Verify an ECDSA signature.
///
/// Returns `True` if the signature is valid, `False` otherwise.
///
/// ## Examples
///
/// ```gleam
/// let is_valid = ecdsa.verify(
///   key: public_key,
///   message: <<"hello":utf8>>,
///   signature: signature,
///   hash: crypto.Sha256,
/// )
/// ```
///
@external(erlang, "gleam_crypto_ecdsa_ffi", "verify")
@external(javascript, "../../gleam_crypto_ecdsa_ffi.mjs", "verify")
pub fn verify(
  key key: PublicKey,
  message message: BitArray,
  signature signature: BitArray,
  hash hash: HashAlgorithm,
) -> Bool
