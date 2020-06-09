import gleam/atom.{Atom}
import gleam/bit_string
import gleam/crypto
import gleam/should

external fn ensure_all_started(Atom) -> Result(List(Atom), Nil) = "application" "ensure_all_started"

pub fn random_bytes_test() {
let Ok(_) = ensure_all_started(atom.create_from_string("crypto"))
  crypto.strong_random_bytes(0)
  |> should.equal(bit_string.from_string(""))
  crypto.strong_random_bytes(10)
  |> bit_string.byte_size()
  |> should.equal(10)
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
