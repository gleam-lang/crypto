import gleam/bit_string
import gleam/crypto
import gleam/should

pub fn secure_compare_test() {
  crypto.secure_compare(
    bit_string.from_string("ab"),
    bit_string.from_string("ab"),
  )
  |> should.equal(True)

  crypto.secure_compare(
    bit_string.from_string("ab"),
    bit_string.from_string("az"),
  )
  |> should.equal(False)

  crypto.secure_compare(bit_string.from_string(""), bit_string.from_string(""))
  |> should.equal(True)

  crypto.secure_compare(
    bit_string.from_string("ab"),
    bit_string.from_string("a"),
  )
  |> should.equal(False)
}
