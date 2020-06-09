import gleam/crypto
import gleam/should

pub fn secure_compare_test() {
  crypto.secure_compare(<<10, 200>>, <<10, 200>>)
  |> should.equal(True)

  crypto.secure_compare(<<10, 200>>, <<10, 201>>)
  |> should.equal(False)

  crypto.secure_compare(<<>>, <<>>)
  |> should.equal(True)

  crypto.secure_compare(<<10, 200>>, <<10>>)
  |> should.equal(False)
}
