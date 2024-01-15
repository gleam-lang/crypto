//// Set of cryptographic functions.

import gleam/bit_array
import gleam/string
import gleam/int
import gleam/result

/// Generates N bytes randomly uniform 0..255, and returns the result in a binary.
///
/// Uses a cryptographically secure prng seeded and periodically mixed with
/// operating system provided entropy.
/// By default this is the RAND_bytes method from OpenSSL.
///
/// https://erlang.org/doc/man/crypto.html#strong_rand_bytes-1
@external(erlang, "crypto", "strong_rand_bytes")
pub fn strong_random_bytes(a: Int) -> BitArray

pub type HashAlgorithm {
  Sha224
  Sha256
  Sha384
  Sha512
}

/// Computes a digest of the input bit string.
@external(erlang, "crypto", "hash")
pub fn hash(a: HashAlgorithm, b: BitArray) -> BitArray

type Hmac {
  Hmac
}

@external(erlang, "crypto", "mac")
fn erl_hmac(a: Hmac, b: HashAlgorithm, c: BitArray, d: BitArray) -> BitArray

/// Calculates the HMAC (hash-based message authentication code) for a bit
/// string.
///
/// Based on the Erlang [`crypto:mac`](https://www.erlang.org/doc/man/crypto.html#mac-4)
/// function.
///
pub fn hmac(data: BitArray, algorithm: HashAlgorithm, key: BitArray) {
  erl_hmac(Hmac, algorithm, key, data)
}

fn do_secure_compare(left: BitArray, right: BitArray, accumulator: Int) -> Bool {
  case left, right {
    <<x, left:bits>>, <<y, right:bits>> -> {
      let accumulator =
        int.bitwise_or(accumulator, int.bitwise_exclusive_or(x, y))
      do_secure_compare(left, right, accumulator)
    }
    _, _ -> accumulator == 0
  }
}

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
    <<"HS224":utf8>> -> Ok(Sha224)
    <<"HS256":utf8>> -> Ok(Sha256)
    <<"HS384":utf8>> -> Ok(Sha384)
    <<"HS512":utf8>> -> Ok(Sha512)
    _ -> Error(Nil)
  })
  let challenge = hmac(<<text:utf8>>, digest_type, secret)
  case secure_compare(challenge, signature) {
    True -> Ok(payload)
    False -> Error(Nil)
  }
}
