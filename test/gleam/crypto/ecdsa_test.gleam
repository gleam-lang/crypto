import gleam/crypto
import gleam/crypto/ecdsa
import gleeunit/should

pub fn generate_key_pair_p256_test() {
  let assert Ok(#(private_key, public_key)) =
    ecdsa.generate_key_pair(curve: ecdsa.P256)

  let message = <<"Hello, ECDSA P256!":utf8>>
  let signature =
    ecdsa.sign(key: private_key, message: message, hash: crypto.Sha256)

  ecdsa.verify(
    key: public_key,
    message: message,
    signature: signature,
    hash: crypto.Sha256,
  )
  |> should.equal(True)
}

pub fn generate_key_pair_p384_test() {
  let assert Ok(#(private_key, public_key)) =
    ecdsa.generate_key_pair(curve: ecdsa.P384)

  let message = <<"Hello, ECDSA P384!":utf8>>
  let signature =
    ecdsa.sign(key: private_key, message: message, hash: crypto.Sha384)

  ecdsa.verify(
    key: public_key,
    message: message,
    signature: signature,
    hash: crypto.Sha384,
  )
  |> should.equal(True)
}

pub fn generate_key_pair_p521_test() {
  let assert Ok(#(private_key, public_key)) =
    ecdsa.generate_key_pair(curve: ecdsa.P521)

  let message = <<"Hello, ECDSA P521!":utf8>>
  let signature =
    ecdsa.sign(key: private_key, message: message, hash: crypto.Sha512)

  ecdsa.verify(
    key: public_key,
    message: message,
    signature: signature,
    hash: crypto.Sha512,
  )
  |> should.equal(True)
}

pub fn verify_wrong_message_test() {
  let assert Ok(#(private_key, public_key)) =
    ecdsa.generate_key_pair(curve: ecdsa.P256)

  let message = <<"Original message":utf8>>
  let signature =
    ecdsa.sign(key: private_key, message: message, hash: crypto.Sha256)

  ecdsa.verify(
    key: public_key,
    message: <<"Different message":utf8>>,
    signature: signature,
    hash: crypto.Sha256,
  )
  |> should.equal(False)
}

pub fn public_key_from_private_test() {
  let assert Ok(#(private_key, public_key)) =
    ecdsa.generate_key_pair(curve: ecdsa.P256)

  let derived_public_key = ecdsa.public_key_from_private(key: private_key)

  let message = <<"Derived ECDSA key test":utf8>>
  let signature =
    ecdsa.sign(key: private_key, message: message, hash: crypto.Sha256)

  ecdsa.verify(
    key: derived_public_key,
    message: message,
    signature: signature,
    hash: crypto.Sha256,
  )
  |> should.equal(True)

  ecdsa.verify(
    key: public_key,
    message: message,
    signature: signature,
    hash: crypto.Sha256,
  )
  |> should.equal(True)
}

pub fn key_export_import_pem_test() {
  let assert Ok(#(private_key, _public_key)) =
    ecdsa.generate_key_pair(curve: ecdsa.P256)

  let private_pem =
    ecdsa.private_key_to_bytes(key: private_key, format: crypto.Pem)
  let public_key = ecdsa.public_key_from_private(key: private_key)
  let public_pem =
    ecdsa.public_key_to_bytes(key: public_key, format: crypto.Pem)

  let assert Ok(imported_private) =
    ecdsa.private_key(private_pem, format: crypto.Pem)
  let assert Ok(imported_public) =
    ecdsa.public_key(public_pem, format: crypto.Pem)

  let message = <<"ECDSA PEM import/export test":utf8>>
  let signature =
    ecdsa.sign(key: imported_private, message: message, hash: crypto.Sha256)

  ecdsa.verify(
    key: imported_public,
    message: message,
    signature: signature,
    hash: crypto.Sha256,
  )
  |> should.equal(True)
}

pub fn key_export_import_der_test() {
  let assert Ok(#(private_key, _public_key)) =
    ecdsa.generate_key_pair(curve: ecdsa.P256)

  let private_der =
    ecdsa.private_key_to_bytes(key: private_key, format: crypto.Der)
  let public_key = ecdsa.public_key_from_private(key: private_key)
  let public_der =
    ecdsa.public_key_to_bytes(key: public_key, format: crypto.Der)

  let assert Ok(imported_private) =
    ecdsa.private_key(private_der, format: crypto.Der)
  let assert Ok(imported_public) =
    ecdsa.public_key(public_der, format: crypto.Der)

  let message = <<"ECDSA DER import/export test":utf8>>
  let signature =
    ecdsa.sign(key: imported_private, message: message, hash: crypto.Sha256)

  ecdsa.verify(
    key: imported_public,
    message: message,
    signature: signature,
    hash: crypto.Sha256,
  )
  |> should.equal(True)
}
