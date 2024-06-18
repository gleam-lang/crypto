import { BitArray } from "./gleam.mjs";
import {
  Sha224,
  Sha256,
  Sha384,
  Sha512,
  Sha3224,
  Sha3256,
  Sha3384,
  Sha3512,
  Md5,
} from "./gleam/crypto.mjs";

import { noble } from "./noble-hashes-v1.4.0.mjs";
import * as crypto from "node:crypto";

function webCrypto() {
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error("WebCrypto API not supported on this JavaScript runtime");
  }
  return globalThis.crypto;
}

function getHashFunction(algorithm) {
  switch (true) {
    case algorithm instanceof Sha224: return noble.sha224;
    case algorithm instanceof Sha256: return noble.sha256;
    case algorithm instanceof Sha384: return noble.sha384;
    case algorithm instanceof Sha512: return noble.sha512;
    case algorithm instanceof Sha3224: return noble.sha3_224;
    case algorithm instanceof Sha3256: return noble.sha3_256;
    case algorithm instanceof Sha3384: return noble.sha3_384;
    case algorithm instanceof Sha3512: return noble.sha3_512;
    case algorithm instanceof Md5: return md5;
    default: throw new Error("Unsupported algorithm");
  }
}

function md5(buffer) {
  const hasher = crypto.createHash("md5");
  hasher.update(buffer);
  return new Uint8Array(hasher.digest());
}

export function strongRandomBytes(n) {
  const array = new Uint8Array(n);
  webCrypto().getRandomValues(array);
  return new BitArray(array);
}

function crypto_hmac(data, algorithm, key) {
   const hmac = crypto.createHmac(algorithm, key.buffer);
   hmac.update(data.buffer);
   const array = new Uint8Array(hmac.digest());
   return new BitArray(array);
}

export function hmac(data, algorithm, key) {
  if (algorithm instanceof Md5) {
    return crypto_hmac(data, "md5", key)
  } else {
    return new BitArray(noble.hmac(getHashFunction(algorithm), key.buffer, data.buffer));
  }
}

export function hash(algorithm, data) {
  const hasher = getHashFunction(algorithm);
  return new BitArray(hasher(data.buffer));
}
