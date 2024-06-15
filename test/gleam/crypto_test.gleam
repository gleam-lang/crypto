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

pub fn hash_sha256_test() {
  crypto.hash(crypto.Sha256, <<"hi":utf8>>)
  |> should.equal(<<
    143, 67, 67, 70, 100, 143, 107, 150, 223, 137, 221, 169, 1, 197, 23, 107, 16,
    166, 216, 57, 97, 221, 60, 26, 200, 139, 89, 178, 220, 50, 122, 164,
  >>)
}

pub fn hash_sha224_test() {
  crypto.hash(crypto.Sha224, <<"hi":utf8>>)
  |> should.equal(<<
    26, 21, 188, 163, 228, 237, 58, 184, 35, 103, 198, 196, 52, 248, 108, 65, 4,
    11, 218, 197, 119, 250, 28, 45, 230, 44, 59, 224,
  >>)
}

pub fn hash_sha384_test() {
  crypto.hash(crypto.Sha384, <<"hi":utf8>>)
  |> should.equal(<<
    7, 145, 0, 109, 248, 18, 132, 119, 36, 79, 83, 208, 253, 206, 33, 13, 184,
    31, 85, 117, 117, 16, 226, 106, 206, 227, 92, 24, 166, 188, 234, 162, 141,
    205, 187, 253, 109, 192, 65, 185, 180, 220, 123, 27, 84, 227, 127, 82,
  >>)
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

pub fn hash_sha3_224_test() {
  crypto.hash(crypto.Sha3224, <<"hi":utf8>>)
  |> should.equal(<<
    69, 56, 170, 204, 108, 202, 225, 103, 235, 70, 43, 210, 214, 206, 211, 83,
    126, 223, 111, 141, 136, 175, 112, 155, 231, 177, 48, 192,
  >>)
}

pub fn hash_sha3_256_test() {
  crypto.hash(crypto.Sha3256, <<"hi":utf8>>)
  |> should.equal(<<
    179, 156, 20, 200, 218, 59, 35, 129, 31, 100, 21, 183, 224, 179, 53, 38, 215,
    224, 122, 70, 242, 207, 4, 132, 23, 148, 53, 118, 126, 74, 136, 4,
  >>)
}

pub fn hash_sha3_384_test() {
  crypto.hash(crypto.Sha3384, <<"hi":utf8>>)
  |> should.equal(<<
    26, 63, 130, 34, 74, 227, 192, 147, 61, 151, 199, 226, 229, 212, 139, 115,
    249, 62, 173, 249, 16, 87, 161, 181, 77, 78, 189, 217, 236, 55, 189, 77, 115,
    200, 251, 155, 150, 81, 93, 171, 252, 111, 160, 163, 55, 145, 243, 212,
  >>)
}

pub fn hash_sha3_512_test() {
  crypto.hash(crypto.Sha3512, <<"hi":utf8>>)
  |> should.equal(<<
    21, 64, 19, 203, 129, 64, 199, 83, 240, 172, 53, 141, 166, 17, 15, 226, 55,
    72, 27, 38, 199, 92, 61, 220, 27, 89, 234, 249, 221, 123, 70, 160, 163, 174,
    178, 206, 241, 100, 179, 200, 45, 101, 179, 138, 78, 38, 234, 153, 48, 183,
    178, 203, 60, 1, 218, 75, 163, 49, 201, 94, 98, 204, 185, 195,
  >>)
}

pub fn hash_md5_test() {
  crypto.hash(crypto.Md5, <<"hi":utf8>>)
  |> should.equal(<<
    73, 246, 138, 92, 132, 147, 236, 44, 11, 244, 137, 130, 28, 33, 252, 59,
  >>)
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

pub fn hmac_sha3_224_test() {
  <<"Aladin":utf8>>
  |> crypto.hmac(crypto.Sha3224, <<"secret":utf8>>)
  |> should.equal(<<
    232, 220, 105, 240, 79, 34, 133, 213, 124, 62, 178, 35, 67, 179, 211, 229,
    98, 219, 225, 97, 239, 143, 246, 153, 203, 183, 117, 139,
  >>)
}

pub fn hmac_sha3_256_test() {
  <<"Aladin":utf8>>
  |> crypto.hmac(crypto.Sha3256, <<"secret":utf8>>)
  |> should.equal(<<
    173, 168, 107, 108, 225, 130, 112, 44, 253, 29, 220, 36, 255, 204, 189, 191,
    217, 211, 240, 174, 4, 201, 209, 254, 138, 89, 214, 224, 24, 123, 114, 171,
  >>)
}

pub fn hmac_sha3_384_test() {
  <<"Aladin":utf8>>
  |> crypto.hmac(crypto.Sha3384, <<"secret":utf8>>)
  |> should.equal(<<
    188, 250, 41, 176, 237, 143, 249, 135, 114, 39, 133, 97, 194, 116, 201, 135,
    172, 105, 174, 188, 174, 188, 99, 63, 207, 232, 8, 185, 249, 92, 99, 203, 81,
    74, 229, 79, 93, 153, 134, 129, 233, 216, 153, 206, 226, 211, 19, 52,
  >>)
}

pub fn hmac_sha3_512_test() {
  <<"Aladin":utf8>>
  |> crypto.hmac(crypto.Sha3512, <<"secret":utf8>>)
  |> should.equal(<<
    183, 220, 43, 80, 10, 76, 189, 8, 173, 58, 215, 174, 241, 115, 117, 140, 130,
    167, 203, 72, 80, 39, 238, 148, 20, 219, 61, 70, 197, 48, 143, 89, 182, 173,
    232, 212, 242, 140, 99, 20, 135, 99, 41, 36, 3, 191, 158, 198, 28, 54, 25,
    24, 123, 179, 13, 120, 191, 195, 205, 148, 4, 84, 26, 115,
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

pub fn sign_message_3224_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha3224)
  |> should.equal("SFMzMjI0.SGVsbG8h.hER6RkviDh6bq8d3cZxxeMFEQmW6bN8kwukx6Q")

  crypto.sign_message(<<"Hello!":utf8>>, <<"secret2":utf8>>, crypto.Sha3224)
  |> should.equal("SFMzMjI0.SGVsbG8h.mS7eAl6w02Q6O8z-2zaAXxy3VdHE-n5ArpwF-Q")
}

pub fn sign_message_3256_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha3256)
  |> should.equal(
    "SFMzMjU2.SGVsbG8h.Az5595iJ9pb53uxffgKkug7Y9jE1Zp_8p1nfIYSbORk",
  )

  crypto.sign_message(<<"Hello!":utf8>>, <<"secret2":utf8>>, crypto.Sha3256)
  |> should.equal(
    "SFMzMjU2.SGVsbG8h.b1XrlYvzyKjTGl9y7cj9kdGQI1cfIqCu0iltf38ZHno",
  )
}

pub fn sign_message_3384_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha3384)
  |> should.equal(
    "SFMzMzg0.SGVsbG8h.N1kJfavh4lVUrhbFQxAILkHbEYQzd9jz2S0qePpalT7vMFqp5xRLpTIT9FT2DrTj",
  )

  crypto.sign_message(<<"Hello!":utf8>>, <<"secret2":utf8>>, crypto.Sha3384)
  |> should.equal(
    "SFMzMzg0.SGVsbG8h.G0WRG9XdDE6Y-kd5MkZP1QzONWTGBSnyj9IL-5TgZdIB_Hmv9mT3lkM39NTqwJph",
  )
}

pub fn sign_message_3512_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha3512)
  |> should.equal(
    "SFMzNTEy.SGVsbG8h.fGuDx_7ML4x8x8e4oGiLbigorLtDg3RA3IPUNCZjFwGLR7Mhz2x3IG6jSKwftvbMuKhnbEtkGOIXe3pNGPebFw",
  )

  crypto.sign_message(<<"Hello!":utf8>>, <<"secret2":utf8>>, crypto.Sha3512)
  |> should.equal(
    "SFMzNTEy.SGVsbG8h.Hfq7oz53v2Gl_VkL1p54ngHJexqOTSU7j8ps4q14LnioQNOsWb5EV2QLuFSxK8wvypS0ppZiBKhkbZrBN7xsiA",
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

pub fn verify_signed_message_3224_ok_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha3224)
  |> crypto.verify_signed_message(<<"secret":utf8>>)
  |> should.equal(Ok(<<"Hello!":utf8>>))
}

pub fn verify_signed_message_3224_ko_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha3224)
  |> crypto.verify_signed_message(<<"other":utf8>>)
  |> should.equal(Error(Nil))
}

pub fn verify_signed_message_3256_ok_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha3256)
  |> crypto.verify_signed_message(<<"secret":utf8>>)
  |> should.equal(Ok(<<"Hello!":utf8>>))
}

pub fn verify_signed_message_3256_ko_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha3256)
  |> crypto.verify_signed_message(<<"other":utf8>>)
  |> should.equal(Error(Nil))
}


pub fn verify_signed_message_3384_ok_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha3384)
  |> crypto.verify_signed_message(<<"secret":utf8>>)
  |> should.equal(Ok(<<"Hello!":utf8>>))
}

pub fn verify_signed_message_3384_ko_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha3384)
  |> crypto.verify_signed_message(<<"other":utf8>>)
  |> should.equal(Error(Nil))
}

pub fn verify_signed_message_3512_ok_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha3512)
  |> crypto.verify_signed_message(<<"secret":utf8>>)
  |> should.equal(Ok(<<"Hello!":utf8>>))
}

pub fn verify_signed_message_3512_ko_test() {
  crypto.sign_message(<<"Hello!":utf8>>, <<"secret":utf8>>, crypto.Sha3512)
  |> crypto.verify_signed_message(<<"other":utf8>>)
  |> should.equal(Error(Nil))
}
