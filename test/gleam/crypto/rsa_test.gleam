import gleam/crypto
import gleam/crypto/rsa
import gleeunit/should

pub fn generate_key_pair_2048_test() {
  let assert Ok(#(private_key, public_key)) = rsa.generate_key_pair(bits: 2048)

  let message = <<"Too many secrets":utf8>>
  let signature =
    rsa.sign(
      key: private_key,
      message: message,
      hash: crypto.Sha256,
      padding: rsa.Pss,
    )

  rsa.verify(
    key: public_key,
    message: message,
    signature: signature,
    hash: crypto.Sha256,
    padding: rsa.Pss,
  )
  |> should.equal(True)
}

pub fn sign_verify_pss_sha256_test() {
  let assert Ok(#(private_key, public_key)) = rsa.generate_key_pair(bits: 2048)

  let message = <<"Test message for RSA-PSS":utf8>>
  let signature =
    rsa.sign(
      key: private_key,
      message: message,
      hash: crypto.Sha256,
      padding: rsa.Pss,
    )

  rsa.verify(
    key: public_key,
    message: message,
    signature: signature,
    hash: crypto.Sha256,
    padding: rsa.Pss,
  )
  |> should.equal(True)

  rsa.verify(
    key: public_key,
    message: <<"Wrong message":utf8>>,
    signature: signature,
    hash: crypto.Sha256,
    padding: rsa.Pss,
  )
  |> should.equal(False)
}

pub fn sign_verify_pkcs1v15_sha256_test() {
  let assert Ok(#(private_key, public_key)) = rsa.generate_key_pair(bits: 2048)

  let message = <<"Test message for RSA-PKCS1v15":utf8>>
  let signature =
    rsa.sign(
      key: private_key,
      message: message,
      hash: crypto.Sha256,
      padding: rsa.Pkcs1v15,
    )

  rsa.verify(
    key: public_key,
    message: message,
    signature: signature,
    hash: crypto.Sha256,
    padding: rsa.Pkcs1v15,
  )
  |> should.equal(True)
}

pub fn public_key_from_private_test() {
  let assert Ok(#(private_key, public_key)) = rsa.generate_key_pair(bits: 2048)

  let derived_public_key = rsa.public_key_from_private(key: private_key)

  let message = <<"Derived key test":utf8>>
  let signature =
    rsa.sign(
      key: private_key,
      message: message,
      hash: crypto.Sha256,
      padding: rsa.Pss,
    )

  rsa.verify(
    key: derived_public_key,
    message: message,
    signature: signature,
    hash: crypto.Sha256,
    padding: rsa.Pss,
  )
  |> should.equal(True)

  rsa.verify(
    key: public_key,
    message: message,
    signature: signature,
    hash: crypto.Sha256,
    padding: rsa.Pss,
  )
  |> should.equal(True)
}

pub fn key_export_import_pem_pkcs1_test() {
  let assert Ok(#(private_key, _public_key)) = rsa.generate_key_pair(bits: 2048)

  let private_pem =
    rsa.private_key_to_bytes(
      key: private_key,
      format: crypto.Pem,
      key_format: rsa.Pkcs1,
    )
  let public_key = rsa.public_key_from_private(key: private_key)
  let public_pem = rsa.public_key_to_bytes(key: public_key, format: crypto.Pem)

  let assert Ok(imported_private) =
    rsa.private_key(private_pem, format: crypto.Pem)
  let assert Ok(imported_public) =
    rsa.public_key(public_pem, format: crypto.Pem)

  let message = <<"Import/export test":utf8>>
  let signature =
    rsa.sign(
      key: imported_private,
      message: message,
      hash: crypto.Sha256,
      padding: rsa.Pss,
    )

  rsa.verify(
    key: imported_public,
    message: message,
    signature: signature,
    hash: crypto.Sha256,
    padding: rsa.Pss,
  )
  |> should.equal(True)
}

pub fn key_export_import_pem_pkcs8_test() {
  let assert Ok(#(private_key, _public_key)) = rsa.generate_key_pair(bits: 2048)

  let private_pem =
    rsa.private_key_to_bytes(
      key: private_key,
      format: crypto.Pem,
      key_format: rsa.Pkcs8,
    )
  let public_key = rsa.public_key_from_private(key: private_key)
  let public_pem = rsa.public_key_to_bytes(key: public_key, format: crypto.Pem)

  let assert Ok(imported_private) =
    rsa.private_key(private_pem, format: crypto.Pem)
  let assert Ok(imported_public) =
    rsa.public_key(public_pem, format: crypto.Pem)

  let message = <<"PKCS8 import/export test":utf8>>
  let signature =
    rsa.sign(
      key: imported_private,
      message: message,
      hash: crypto.Sha256,
      padding: rsa.Pss,
    )

  rsa.verify(
    key: imported_public,
    message: message,
    signature: signature,
    hash: crypto.Sha256,
    padding: rsa.Pss,
  )
  |> should.equal(True)
}

pub fn key_export_import_der_pkcs1_test() {
  let assert Ok(#(private_key, _public_key)) = rsa.generate_key_pair(bits: 2048)

  let private_der =
    rsa.private_key_to_bytes(
      key: private_key,
      format: crypto.Der,
      key_format: rsa.Pkcs1,
    )
  let public_key = rsa.public_key_from_private(key: private_key)
  let public_der = rsa.public_key_to_bytes(key: public_key, format: crypto.Der)

  let assert Ok(imported_private) =
    rsa.private_key(private_der, format: crypto.Der)
  let assert Ok(imported_public) =
    rsa.public_key(public_der, format: crypto.Der)

  let message = <<"DER import/export test":utf8>>
  let signature =
    rsa.sign(
      key: imported_private,
      message: message,
      hash: crypto.Sha256,
      padding: rsa.Pkcs1v15,
    )

  rsa.verify(
    key: imported_public,
    message: message,
    signature: signature,
    hash: crypto.Sha256,
    padding: rsa.Pkcs1v15,
  )
  |> should.equal(True)
}

pub fn key_export_import_der_pkcs8_test() {
  let assert Ok(#(private_key, _public_key)) = rsa.generate_key_pair(bits: 2048)

  let private_der =
    rsa.private_key_to_bytes(
      key: private_key,
      format: crypto.Der,
      key_format: rsa.Pkcs8,
    )
  let public_key = rsa.public_key_from_private(key: private_key)
  let public_der = rsa.public_key_to_bytes(key: public_key, format: crypto.Der)

  let assert Ok(imported_private) =
    rsa.private_key(private_der, format: crypto.Der)
  let assert Ok(imported_public) =
    rsa.public_key(public_der, format: crypto.Der)

  let message = <<"DER PKCS8 import/export test":utf8>>
  let signature =
    rsa.sign(
      key: imported_private,
      message: message,
      hash: crypto.Sha256,
      padding: rsa.Pkcs1v15,
    )

  rsa.verify(
    key: imported_public,
    message: message,
    signature: signature,
    hash: crypto.Sha256,
    padding: rsa.Pkcs1v15,
  )
  |> should.equal(True)
}
