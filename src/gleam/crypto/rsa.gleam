//// RSA cryptographic operations for signing and verification.

import gleam/crypto.{type HashAlgorithm, type KeyFormat}

/// RSA private key for signing operations.
pub type PrivateKey

/// RSA public key for verification operations.
pub type PublicKey

/// RSA signature padding schemes.
pub type Padding {
  /// PKCS#1 v1.5 padding. Widely supported, deterministic signatures.
  Pkcs1v15
  /// Probabilistic Signature Scheme. Modern, randomized.
  Pss
}

/// RSA private key export format.
pub type PrivateKeyFormat {
  /// PKCS#1 RSAPrivateKey format (legacy).
  Pkcs1
  /// PKCS#8 PrivateKeyInfo format (preferred, standard).
  Pkcs8
}

/// Generate a new RSA key pair with the specified bit size.
///
/// Common sizes are 2048, 3072, or 4096 bits.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(#(private_key, public_key)) = rsa.generate_key_pair(bits: 2048)
/// ```
///
@external(erlang, "gleam_crypto_rsa_ffi", "generate_key_pair")
@external(javascript, "../../gleam_crypto_rsa_ffi.mjs", "generateKeyPair")
pub fn generate_key_pair(
  bits bits: Int,
) -> Result(#(PrivateKey, PublicKey), Nil)

/// Import an RSA private key from PEM or DER encoded data.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(key) = rsa.private_key(pem_data, format: crypto.Pem)
/// ```
///
@external(erlang, "gleam_crypto_rsa_ffi", "private_key")
@external(javascript, "../../gleam_crypto_rsa_ffi.mjs", "privateKey")
pub fn private_key(
  data: BitArray,
  format format: KeyFormat,
) -> Result(PrivateKey, Nil)

/// Import an RSA public key from PEM or DER encoded data.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(key) = rsa.public_key(pem_data, format: crypto.Pem)
/// ```
///
@external(erlang, "gleam_crypto_rsa_ffi", "public_key")
@external(javascript, "../../gleam_crypto_rsa_ffi.mjs", "publicKey")
pub fn public_key(
  data: BitArray,
  format format: KeyFormat,
) -> Result(PublicKey, Nil)

/// Export an RSA private key to PEM or DER format.
///
@external(erlang, "gleam_crypto_rsa_ffi", "private_key_to_bytes")
@external(javascript, "../../gleam_crypto_rsa_ffi.mjs", "privateKeyToBytes")
pub fn private_key_to_bytes(
  key key: PrivateKey,
  format format: KeyFormat,
  key_format key_format: PrivateKeyFormat,
) -> BitArray

/// Export an RSA public key to PEM or DER format.
///
@external(erlang, "gleam_crypto_rsa_ffi", "public_key_to_bytes")
@external(javascript, "../../gleam_crypto_rsa_ffi.mjs", "publicKeyToBytes")
pub fn public_key_to_bytes(
  key key: PublicKey,
  format format: KeyFormat,
) -> BitArray

/// Extract the public key from an RSA private key.
///
@external(erlang, "gleam_crypto_rsa_ffi", "public_key_from_private")
@external(javascript, "../../gleam_crypto_rsa_ffi.mjs", "publicKeyFromPrivate")
pub fn public_key_from_private(key key: PrivateKey) -> PublicKey

/// Sign a message using an RSA private key.
///
/// ## Examples
///
/// ```gleam
/// let signature = rsa.sign(
///   key: private_key,
///   message: <<"hello":utf8>>,
///   hash: crypto.Sha256,
///   padding: rsa.Pss,
/// )
/// ```
///
@external(erlang, "gleam_crypto_rsa_ffi", "sign")
@external(javascript, "../../gleam_crypto_rsa_ffi.mjs", "sign")
pub fn sign(
  key key: PrivateKey,
  message message: BitArray,
  hash hash: HashAlgorithm,
  padding padding: Padding,
) -> BitArray

/// Verify an RSA signature.
///
/// Returns `True` if the signature is valid, `False` otherwise.
///
/// ## Examples
///
/// ```gleam
/// let is_valid = rsa.verify(
///   key: public_key,
///   message: <<"hello":utf8>>,
///   signature: signature,
///   hash: crypto.Sha256,
///   padding: rsa.Pss,
/// )
/// ```
///
@external(erlang, "gleam_crypto_rsa_ffi", "verify")
@external(javascript, "../../gleam_crypto_rsa_ffi.mjs", "verify")
pub fn verify(
  key key: PublicKey,
  message message: BitArray,
  signature signature: BitArray,
  hash hash: HashAlgorithm,
  padding padding: Padding,
) -> Bool
