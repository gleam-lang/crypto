//// Set of cryptographic functions.

import gleam/bit_array
import gleam/int
import gleam/result
import gleam/string

/// Generates a specified number of bytes randomly uniform 0..255, and returns
/// the result in a binary.
///
/// On Erlang this uses a cryptographically secure prng seeded and periodically
/// mixed with / operating system provided entropy. By default this is the
/// RAND_bytes method from OpenSSL.
/// <https://erlang.org/doc/man/crypto.html#strong_rand_bytes-1>
///
/// On JavaScript the WebCrypto API is used.
///
@external(erlang, "crypto", "strong_rand_bytes")
@external(javascript, "../gleam_crypto_ffi.mjs", "strongRandomBytes")
pub fn strong_random_bytes(a: Int) -> BitArray

pub type HashAlgorithm {
  Sha224
  Sha256
  Sha384
  Sha512
  /// The MD5 hash algorithm is considered weak and should not be used for
  /// security purposes. It may still be useful for non-security purposes or for
  /// compatibility with existing systems.
  Md5
  /// The SHA1 hash algorithm is considered weak and should not be used for
  /// security purposes. It may still be useful for non-security purposes or for
  /// compatibility with existing systems.
  Sha1
}

/// Computes a digest of the input bit string.
@external(erlang, "gleam_crypto_ffi", "hash")
@external(javascript, "../gleam_crypto_ffi.mjs", "hash")
pub fn hash(a: HashAlgorithm, b: BitArray) -> BitArray

pub type HashState

/// Starts hash algorithm for streaming
@external(erlang, "gleam_crypto_ffi", "hash_init")
@external(javascript, "../gleam_crypto_ffi.mjs", "hashInit")
pub fn hash_init(a: HashAlgorithm) -> HashState

/// Starts hash algorithm for streaming
@external(erlang, "crypto", "hash_update")
@external(javascript, "../gleam_crypto_ffi.mjs", "hashUpdate")
pub fn hash_update(state: HashState, data: BitArray) -> HashState

/// Starts hash algorithm for streaming
@external(erlang, "crypto", "hash_final")
@external(javascript, "../gleam_crypto_ffi.mjs", "hashFinal")
pub fn hash_final(state: HashState) -> BitArray

/// Calculates the HMAC (hash-based message authentication code) for a bit
/// string.
///
/// Based on the Erlang [`crypto:mac`](https://www.erlang.org/doc/man/crypto.html#mac-4)
/// function, or the [`node:crypto.createHmac`](https://nodejs.org/api/crypto.html#cryptocreatehmacalgorithm-key-options)
/// function on JavaScript.
///
@external(erlang, "gleam_crypto_ffi", "hmac")
@external(javascript, "../gleam_crypto_ffi.mjs", "hmac")
pub fn hmac(data: BitArray, algorithm: HashAlgorithm, key: BitArray) -> BitArray

/// Compares the two binaries in constant-time to avoid timing attacks.
///
/// For more details see: http://codahale.com/a-lesson-in-timing-attacks/
///
pub fn secure_compare(left: BitArray, right: BitArray) -> Bool {
  case bit_array.byte_size(left) == bit_array.byte_size(right) {
    True -> do_secure_compare(left, right, 0)
    False -> False
  }
}

fn do_secure_compare(left: BitArray, right: BitArray, accumulator: Int) -> Bool {
  case left, right {
    <<x, left:bytes>>, <<y, right:bytes>> -> {
      let accumulator =
        int.bitwise_or(accumulator, int.bitwise_exclusive_or(x, y))
      do_secure_compare(left, right, accumulator)
    }
    _, _ -> left == right && accumulator == 0
  }
}

// Based off of https://github.com/elixir-plug/plug_crypto/blob/v1.2.1/lib/plug/crypto/message_verifier.ex#L1
//
/// Sign a message which can later be verified using the `verify_signed_message`
/// function to detect if the message has been tampered with.
///
/// A web application could use this verifier to sign HTTP cookies. The data can
/// be read by the user, but cannot be tampered with.
///
pub fn sign_message(
  message: BitArray,
  secret: BitArray,
  digest_type: HashAlgorithm,
) -> String {
  let input = signing_input(digest_type, message)
  let signature = hmac(<<input:utf8>>, digest_type, secret)

  string.concat([input, ".", bit_array.base64_url_encode(signature, False)])
}

fn signing_input(digest_type: HashAlgorithm, message: BitArray) -> String {
  let protected = case digest_type {
    Sha224 -> "HS224"
    Sha256 -> "HS256"
    Sha384 -> "HS384"
    Sha512 -> "HS512"
    Sha1 -> "HS1"
    Md5 -> "HMD5"
  }
  string.concat([
    bit_array.base64_url_encode(<<protected:utf8>>, False),
    ".",
    bit_array.base64_url_encode(message, False),
  ])
}

// Based off of https://github.com/elixir-plug/plug_crypto/blob/v1.2.1/lib/plug/crypto/message_verifier.ex#L1
//
/// Verify a message created by the `sign_message` function.
///
pub fn verify_signed_message(
  message: String,
  secret: BitArray,
) -> Result(BitArray, Nil) {
  use #(protected, payload, signature) <- result.then(case
    string.split(message, on: ".")
  {
    [a, b, c] -> Ok(#(a, b, c))
    _ -> Error(Nil)
  })
  let text = string.concat([protected, ".", payload])
  use payload <- result.then(bit_array.base64_url_decode(payload))
  use signature <- result.then(bit_array.base64_url_decode(signature))
  use protected <- result.then(bit_array.base64_url_decode(protected))
  use digest_type <- result.then(case protected {
    // <<"HS224":utf8>>
    <<72, 83, 50, 50, 52>> -> Ok(Sha224)
    // <<"HS256":utf8>>
    <<72, 83, 50, 53, 54>> -> Ok(Sha256)
    // <<"HS384":utf8>>
    <<72, 83, 51, 56, 52>> -> Ok(Sha384)
    // <<"HS512":utf8>>
    <<72, 83, 53, 49, 50>> -> Ok(Sha512)
    // <<"HS1":utf8>>
    <<72, 83, 49>> -> Ok(Sha1)
    // <<"HMD5":utf8>>
    <<72, 77, 68, 53>> -> Ok(Md5)
    _ -> Error(Nil)
  })
  let challenge = hmac(<<text:utf8>>, digest_type, secret)
  case secure_compare(challenge, signature) {
    True -> Ok(payload)
    False -> Error(Nil)
  }
}
