import crypto
import gleam/should

pub fn hello_world_test() {
  crypto.hello_world()
  |> should.equal("Hello, from crypto!")
}
