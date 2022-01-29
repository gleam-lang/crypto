import gleam/bit_string
import gleam/crypto
import gleeunit/should

pub fn random_bytes_test() {
  crypto.strong_random_bytes(0)
  |> should.equal(bit_string.from_string(""))
  crypto.strong_random_bytes(10)
  |> bit_string.byte_size()
  |> should.equal(10)
}

pub fn run_hmac_test() {
  <<"Aladin":utf8>>
  |> crypto.hmac(crypto.Sha256, <<"secret":utf8>>)
  |> should.equal(<<
    207, 2, 100, 225, 165, 99, 237, 213, 117, 62, 198, 249, 0, 167, 50, 19, 252,
    90, 253, 61, 172, 62, 242, 192, 139, 123, 55, 112, 73, 102, 192, 171,
  >>)
}

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
