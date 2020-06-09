import gleam/bit_string.{BitString}
import gleam/bitwise

fn do_secure_compare(left, right, accumulator) {
  case left, right {
    [x, ..left], [y, ..right] -> {
      let accumulator = bitwise.or(accumulator, bitwise.exclusive_or(x, y))
      do_secure_compare(left, right, accumulator)
    }
    [], [] -> accumulator == 0
  }
}

external fn binary_to_list(BitString) -> List(Int) =
  "erlang" "binary_to_list"

/// Compares the two binaries in constant-time to avoid timing attacks.
///
/// For more details see: http://codahale.com/a-lesson-in-timing-attacks/
pub fn secure_compare(left: BitString, right: BitString) {
  case bit_string.byte_size(left) == bit_string.byte_size(right) {
    True -> {
      let left = binary_to_list(left)
      let right = binary_to_list(right)
      do_secure_compare(left, right, 0)
    }
    False -> False
  }
}
