# crypto

A Gleam cryptography library supporting Erlang and JavaScript

[![Package Version](https://img.shields.io/hexpm/v/gleam_crypto)](https://hex.pm/packages/gleam_crypto)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://gleam-crypto.hexdocs.pm/)

```sh
gleam add gleam_crypto@1
```
```gleam
import gleam/crypto

pub fn main() {
  let hash1 = crypto.hash(crypto.Sha512, <<"Hello, Joe!">>)
  let hash2 = crypto.hash(crypto.Sha512, <<"Hello, Mike!">>)
  assert !crypto.secure_compare(hash1, hash2)
}
```

Further documentation can be found at <https://gleam-crypto.hexdocs.pm/>.
