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

pub fn secure_compare1_test() {
  crypto.secure_compare(
    bit_string.from_string("ab"),
    bit_string.from_string("ab"),
  )
  |> should.equal(True)
}

pub fn secure_compare2_test() {
  crypto.secure_compare(
    bit_string.from_string("ab"),
    bit_string.from_string("az"),
  )
  |> should.equal(False)
}

pub fn secure_compare3_test() {
  crypto.secure_compare(bit_string.from_string(""), bit_string.from_string(""))
  |> should.equal(True)
}

pub fn secure_compare4_test() {
  crypto.secure_compare(
    bit_string.from_string("ab"),
    bit_string.from_string("a"),
  )
  |> should.equal(False)
}

pub fn sign_message_256_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha256)
  |> should.equal(
    "SFMyNTY.SGVsbG8h.Ru79YHRxErNruL-fFbL-D1rQX3evRazH8jDlvEUf4TQ",
  )

  crypto.sign_message(<<"Hello!":utf8>>, <<"secret2":utf8>>, crypto.Sha256)
  |> should.equal(
    "SFMyNTY.SGVsbG8h.wNq_17oes1Y0qchSGpfQ7bsc9E8dBYSKh21pJ7A7VjM",
  )
}

pub fn sign_message_224_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha224)
  |> should.equal("SFMyMjQ.SGVsbG8h.Amvf2Hkzu-tgkpKeo9WUBvYiG49VJ_QJB5dAmA")

  crypto.sign_message(<<"Hello!":utf8>>, <<"secret2":utf8>>, crypto.Sha224)
  |> should.equal("SFMyMjQ.SGVsbG8h.NvgZO3AK1MfKlJ4HQnpBRyqZ-rjaolsjc9yAKg")
}

pub fn sign_message_384_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha384)
  |> should.equal(
    "SFMzODQ.SGVsbG8h.r70Xn1OA-6xg7KGyjAHeFIlhE9_a3ybY9Nuh_YWRQRUhiy78LdN6DVfNUKT1fqBO",
  )

  crypto.sign_message(<<"Hello!":utf8>>, <<"secret2":utf8>>, crypto.Sha384)
  |> should.equal(
    "SFMzODQ.SGVsbG8h.2hJEwG3s64Lxiilcqph-C753r8p3WZ7VblfKAgf4WR-DWZH9S9HguO53h-harzu1",
  )
}

pub fn sign_message_512_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha512)
  |> should.equal(
    "SFM1MTI.SGVsbG8h.wzfL_dcJCCgIO3fBd5y4Hz00sNIjVGqJzHfHlOy3_eAvc9oEYAbYQKwCYIyQ7CsHdC5Z1G33XNMd8b-2THtOkQ",
  )

  crypto.sign_message(<<"Hello!":utf8>>, <<"secret2":utf8>>, crypto.Sha512)
  |> should.equal(
    "SFM1MTI.SGVsbG8h.w1i7itKSomlAXJYfffD9edN2Bq_y4rSy4LDbb6MFjp0_6BjmgO3wsI9CHsrb4v-zk8lT1I0qKmmQzjLShj4kjA",
  )
}

pub fn verify_signed_message_256_ok_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha256)
  |> crypto.verify_signed_message(<<"secret":utf8>>)
  |> should.equal(Ok(<<"Hello!":utf8>>))
}

pub fn verify_signed_message_256_ko_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha256)
  |> crypto.verify_signed_message(<<"other":utf8>>)
  |> should.equal(Error(Nil))
}

pub fn verify_signed_message_224_ok_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha224)
  |> crypto.verify_signed_message(<<"secret":utf8>>)
  |> should.equal(Ok(<<"Hello!":utf8>>))
}

pub fn verify_signed_message_224_ko_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha224)
  |> crypto.verify_signed_message(<<"other":utf8>>)
  |> should.equal(Error(Nil))
}

pub fn verify_signed_message_384_ok_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha384)
  |> crypto.verify_signed_message(<<"secret":utf8>>)
  |> should.equal(Ok(<<"Hello!":utf8>>))
}

pub fn verify_signed_message_384_ko_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha384)
  |> crypto.verify_signed_message(<<"other":utf8>>)
  |> should.equal(Error(Nil))
}

pub fn verify_signed_message_512_ok_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha512)
  |> crypto.verify_signed_message(<<"secret":utf8>>)
  |> should.equal(Ok(<<"Hello!":utf8>>))
}

pub fn verify_signed_message_512_ko_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha512)
  |> crypto.verify_signed_message(<<"other":utf8>>)
  |> should.equal(Error(Nil))
}
