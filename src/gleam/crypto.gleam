import gleam/bit_string.{BitString}
import gleam/bitwise

fn do_secure_compare(left, right, accumulator) {
  case left, right {
    <<x, left:binary>>, <<y, right:binary>> -> {
      let accumulator = bitwise.or(accumulator, bitwise.exclusive_or(x, y))
      do_secure_compare(left, right, accumulator)
    }
    <<>>, <<>> -> accumulator == 0
  }
}

/// Compares the two binaries in constant-time to avoid timing attacks.
///
/// For more details see: http://codahale.com/a-lesson-in-timing-attacks/
pub fn secure_compare(left, right) {
  bit_string.byte_size(
    left,
  ) == bit_string.byte_size(right) && do_secure_compare(left, right, 0)
}
