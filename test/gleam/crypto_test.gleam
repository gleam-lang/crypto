import gleam/bit_array
import gleam/crypto
import gleeunit/should

pub fn random_bytes_test() {
  crypto.strong_random_bytes(0)
  |> should.equal(bit_array.from_string(""))
  crypto.strong_random_bytes(10)
  |> bit_array.byte_size()
  |> should.equal(10)
}

pub fn hash_sha1_test() {
  crypto.hash(crypto.Sha1, <<"hi":utf8>>)
  |> should.equal(<<
    194, 43, 95, 145, 120, 52, 38, 9, 66, 141, 111, 81, 178, 197, 175, 76, 11,
    222, 106, 66,
  >>)
}

pub fn hash_sha1_stream_test() {
  crypto.hash_init(crypto.Sha1)
  |> crypto.hash_update(with: <<"hello ":utf8>>)
  |> crypto.hash_update(with: <<"stream":utf8>>)
  |> crypto.digest
  |> should.equal(crypto.hash(crypto.Sha1, <<"hello stream":utf8>>))
}

pub fn hash_sha256_test() {
  crypto.hash(crypto.Sha256, <<"hi":utf8>>)
  |> should.equal(<<
    143, 67, 67, 70, 100, 143, 107, 150, 223, 137, 221, 169, 1, 197, 23, 107, 16,
    166, 216, 57, 97, 221, 60, 26, 200, 139, 89, 178, 220, 50, 122, 164,
  >>)
}

pub fn hash_sha256_stream_test() {
  crypto.hash_init(crypto.Sha256)
  |> crypto.hash_update(with: <<"hello ":utf8>>)
  |> crypto.hash_update(with: <<"stream":utf8>>)
  |> crypto.digest
  |> should.equal(crypto.hash(crypto.Sha256, <<"hello stream":utf8>>))
}

pub fn hash_sha224_test() {
  crypto.hash(crypto.Sha224, <<"hi":utf8>>)
  |> should.equal(<<
    26, 21, 188, 163, 228, 237, 58, 184, 35, 103, 198, 196, 52, 248, 108, 65, 4,
    11, 218, 197, 119, 250, 28, 45, 230, 44, 59, 224,
  >>)
}

pub fn hash_sha224_stream_test() {
  crypto.hash_init(crypto.Sha224)
  |> crypto.hash_update(with: <<"hello ":utf8>>)
  |> crypto.hash_update(with: <<"stream":utf8>>)
  |> crypto.digest
  |> should.equal(crypto.hash(crypto.Sha224, <<"hello stream":utf8>>))
}

pub fn hash_sha384_test() {
  crypto.hash(crypto.Sha384, <<"hi":utf8>>)
  |> should.equal(<<
    7, 145, 0, 109, 248, 18, 132, 119, 36, 79, 83, 208, 253, 206, 33, 13, 184,
    31, 85, 117, 117, 16, 226, 106, 206, 227, 92, 24, 166, 188, 234, 162, 141,
    205, 187, 253, 109, 192, 65, 185, 180, 220, 123, 27, 84, 227, 127, 82,
  >>)
}

pub fn hash_sha384_stream_test() {
  crypto.hash_init(crypto.Sha384)
  |> crypto.hash_update(with: <<"hello ":utf8>>)
  |> crypto.hash_update(with: <<"stream":utf8>>)
  |> crypto.digest
  |> should.equal(crypto.hash(crypto.Sha384, <<"hello stream":utf8>>))
}

pub fn hash_sha512_test() {
  crypto.hash(crypto.Sha512, <<"hi":utf8>>)
  |> should.equal(<<
    21, 10, 20, 237, 91, 234, 108, 199, 49, 207, 134, 196, 21, 102, 172, 66, 122,
    141, 180, 142, 241, 185, 253, 98, 102, 100, 179, 191, 187, 153, 7, 31, 164,
    201, 34, 243, 61, 222, 56, 113, 155, 140, 131, 84, 226, 183, 171, 157, 119,
    224, 230, 127, 193, 40, 67, 146, 10, 113, 46, 115, 213, 88, 225, 151,
  >>)
}

pub fn hash_sha512_stream_test() {
  crypto.hash_init(crypto.Sha512)
  |> crypto.hash_update(with: <<"hello ":utf8>>)
  |> crypto.hash_update(with: <<"stream":utf8>>)
  |> crypto.digest
  |> should.equal(crypto.hash(crypto.Sha512, <<"hello stream":utf8>>))
}

pub fn hash_md5_test() {
  crypto.hash(crypto.Md5, <<"hi":utf8>>)
  |> should.equal(<<
    73, 246, 138, 92, 132, 147, 236, 44, 11, 244, 137, 130, 28, 33, 252, 59,
  >>)
}

pub fn hash_md5_stream_test() {
  crypto.hash_init(crypto.Md5)
  |> crypto.hash_update(with: <<"hello ":utf8>>)
  |> crypto.hash_update(with: <<"stream":utf8>>)
  |> crypto.digest
  |> should.equal(crypto.hash(crypto.Md5, <<"hello stream":utf8>>))
}

pub fn hmac_sha256_test() {
  <<"Aladin":utf8>>
  |> crypto.hmac(crypto.Sha256, <<"secret":utf8>>)
  |> should.equal(<<
    207, 2, 100, 225, 165, 99, 237, 213, 117, 62, 198, 249, 0, 167, 50, 19, 252,
    90, 253, 61, 172, 62, 242, 192, 139, 123, 55, 112, 73, 102, 192, 171,
  >>)
}

pub fn hmac_sha224_test() {
  <<"Aladin":utf8>>
  |> crypto.hmac(crypto.Sha224, <<"secret":utf8>>)
  |> should.equal(<<
    240, 233, 65, 69, 212, 196, 100, 132, 41, 196, 196, 138, 68, 18, 46, 92, 3,
    164, 17, 128, 208, 121, 213, 81, 113, 208, 100, 222,
  >>)
}

pub fn hmac_sha384_test() {
  <<"Aladin":utf8>>
  |> crypto.hmac(crypto.Sha384, <<"secret":utf8>>)
  |> should.equal(<<
    20, 153, 43, 38, 131, 24, 89, 21, 16, 9, 199, 177, 41, 149, 39, 105, 250, 98,
    19, 205, 99, 85, 103, 90, 60, 146, 146, 248, 71, 200, 119, 138, 143, 211, 28,
    199, 223, 132, 81, 116, 131, 53, 129, 201, 194, 12, 142, 203,
  >>)
}

pub fn hmac_sha512_test() {
  <<"Aladin":utf8>>
  |> crypto.hmac(crypto.Sha512, <<"secret":utf8>>)
  |> should.equal(<<
    246, 76, 110, 59, 238, 62, 2, 209, 158, 69, 93, 135, 163, 77, 161, 238, 59,
    160, 60, 66, 220, 202, 26, 48, 237, 14, 53, 239, 74, 128, 194, 103, 182, 14,
    122, 31, 46, 26, 94, 1, 82, 22, 206, 122, 94, 1, 219, 240, 237, 41, 83, 39,
    149, 237, 179, 39, 132, 160, 170, 5, 160, 231, 143, 105,
  >>)
}

pub fn hmac_md5_test() {
  <<"Aladin":utf8>>
  |> crypto.hmac(crypto.Md5, <<"secret":utf8>>)
  |> should.equal(<<
    252, 36, 147, 158, 191, 93, 158, 10, 120, 217, 237, 157, 107, 233, 188, 139,
  >>)
}

pub fn secure_compare1_test() {
  crypto.secure_compare(
    bit_array.from_string("ab"),
    bit_array.from_string("ab"),
  )
  |> should.equal(True)
}

pub fn secure_compare2_test() {
  crypto.secure_compare(
    bit_array.from_string("ab"),
    bit_array.from_string("az"),
  )
  |> should.equal(False)
}

pub fn secure_compare3_test() {
  crypto.secure_compare(bit_array.from_string(""), bit_array.from_string(""))
  |> should.equal(True)
}

pub fn secure_compare4_test() {
  crypto.secure_compare(bit_array.from_string("ab"), bit_array.from_string("a"))
  |> should.equal(False)
}

pub fn sign_message_sha256_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha256)
  |> should.equal(
    "SFMyNTY.SGVsbG8h.Ru79YHRxErNruL-fFbL-D1rQX3evRazH8jDlvEUf4TQ",
  )

  crypto.sign_message(<<"Hello!":utf8>>, <<"secret2":utf8>>, crypto.Sha256)
  |> should.equal(
    "SFMyNTY.SGVsbG8h.wNq_17oes1Y0qchSGpfQ7bsc9E8dBYSKh21pJ7A7VjM",
  )
}

pub fn sign_message_sha224_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha224)
  |> should.equal("SFMyMjQ.SGVsbG8h.Amvf2Hkzu-tgkpKeo9WUBvYiG49VJ_QJB5dAmA")

  crypto.sign_message(<<"Hello!":utf8>>, <<"secret2":utf8>>, crypto.Sha224)
  |> should.equal("SFMyMjQ.SGVsbG8h.NvgZO3AK1MfKlJ4HQnpBRyqZ-rjaolsjc9yAKg")
}

pub fn sign_message_sha384_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha384)
  |> should.equal(
    "SFMzODQ.SGVsbG8h.r70Xn1OA-6xg7KGyjAHeFIlhE9_a3ybY9Nuh_YWRQRUhiy78LdN6DVfNUKT1fqBO",
  )

  crypto.sign_message(<<"Hello!":utf8>>, <<"secret2":utf8>>, crypto.Sha384)
  |> should.equal(
    "SFMzODQ.SGVsbG8h.2hJEwG3s64Lxiilcqph-C753r8p3WZ7VblfKAgf4WR-DWZH9S9HguO53h-harzu1",
  )
}

pub fn sign_message_sha512_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha512)
  |> should.equal(
    "SFM1MTI.SGVsbG8h.wzfL_dcJCCgIO3fBd5y4Hz00sNIjVGqJzHfHlOy3_eAvc9oEYAbYQKwCYIyQ7CsHdC5Z1G33XNMd8b-2THtOkQ",
  )

  crypto.sign_message(<<"Hello!":utf8>>, <<"secret2":utf8>>, crypto.Sha512)
  |> should.equal(
    "SFM1MTI.SGVsbG8h.w1i7itKSomlAXJYfffD9edN2Bq_y4rSy4LDbb6MFjp0_6BjmgO3wsI9CHsrb4v-zk8lT1I0qKmmQzjLShj4kjA",
  )
}

pub fn verify_signed_message_sha256_ok_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha256)
  |> crypto.verify_signed_message(<<"secret":utf8>>)
  |> should.equal(Ok(<<"Hello!":utf8>>))
}

pub fn verify_signed_message_sha256_ko_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha256)
  |> crypto.verify_signed_message(<<"other":utf8>>)
  |> should.equal(Error(Nil))
}

pub fn verify_signed_message_sha224_ok_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha224)
  |> crypto.verify_signed_message(<<"secret":utf8>>)
  |> should.equal(Ok(<<"Hello!":utf8>>))
}

pub fn verify_signed_message_sha224_ko_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha224)
  |> crypto.verify_signed_message(<<"other":utf8>>)
  |> should.equal(Error(Nil))
}

pub fn verify_signed_message_sha384_ok_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha384)
  |> crypto.verify_signed_message(<<"secret":utf8>>)
  |> should.equal(Ok(<<"Hello!":utf8>>))
}

pub fn verify_signed_message_sha384_ko_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha384)
  |> crypto.verify_signed_message(<<"other":utf8>>)
  |> should.equal(Error(Nil))
}

pub fn verify_signed_message_sha512_ok_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha512)
  |> crypto.verify_signed_message(<<"secret":utf8>>)
  |> should.equal(Ok(<<"Hello!":utf8>>))
}

pub fn verify_signed_message_sha512_ko_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha512)
  |> crypto.verify_signed_message(<<"other":utf8>>)
  |> should.equal(Error(Nil))
}

pub fn verify_signed_message_sha1_ok_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha1)
  |> crypto.verify_signed_message(<<"secret":utf8>>)
  |> should.equal(Ok(<<"Hello!":utf8>>))
}

pub fn verify_signed_message_sha1_ko_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha1)
  |> crypto.verify_signed_message(<<"other":utf8>>)
  |> should.equal(Error(Nil))
}
