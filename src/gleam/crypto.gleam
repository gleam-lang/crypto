//// Set of cryptographic functions.

import gleam/bit_string
import gleam/bitwise

/// Generates N bytes randomly uniform 0..255, and returns the result in a binary.
///
/// Uses a cryptographically secure prng seeded and periodically mixed with
/// operating system provided entropy.
/// By default this is the RAND_bytes method from OpenSSL.
///
/// https://erlang.org/doc/man/crypto.html#strong_rand_bytes-1
pub external fn strong_random_bytes(Int) -> BitString =
  "crypto" "strong_rand_bytes"

pub type HashAlgorithm {
  Sha224
  Sha256
  Sha384
  Sha512
}

/// Computes a digest of the input bit string.
pub external fn hash(HashAlgorithm, BitString) -> BitString =
  "crypto" "hash"

type Hmac {
  Hmac
}

external fn erl_hmac(Hmac, HashAlgorithm, BitString, BitString) -> BitString =
  "crypto" "mac"

/// Calculates the HMAC (hash-based message authentication code) for a bit
/// string.
///
/// Based on the Erlang [`crypto:mac`](https://www.erlang.org/doc/man/crypto.html#mac-4)
/// function.
///
pub fn hmac(data: BitString, algorithm: HashAlgorithm, key: BitString) {
  erl_hmac(Hmac, algorithm, key, data)
}

fn do_secure_compare(
  left: BitString,
  right: BitString,
  accumulator: Int,
) -> Bool {
  case left, right {
    <<x, left:bit_string>>, <<y, right:bit_string>> -> {
      let accumulator = bitwise.or(accumulator, bitwise.exclusive_or(x, y))
      do_secure_compare(left, right, accumulator)
    }
    <<>>, <<>> -> accumulator == 0
  }
}

/// Compares the two binaries in constant-time to avoid timing attacks.
///
/// For more details see: http://codahale.com/a-lesson-in-timing-attacks/
///
pub fn secure_compare(left: BitString, right: BitString) -> Bool {
  case bit_string.byte_size(left) == bit_string.byte_size(right) {
    True -> do_secure_compare(left, right, 0)
    False -> False
  }
}
