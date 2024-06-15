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
import * as crypto from "node:crypto";

function webCrypto() {
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error("WebCrypto API not supported on this JavaScript runtime");
  }
  return globalThis.crypto;
}

function algorithmName(algorithm) {
  switch (true) {
    case algorithm instanceof Sha224: return "sha224";
    case algorithm instanceof Sha256: return "sha256";
    case algorithm instanceof Sha256: return "sha256";
    case algorithm instanceof Sha384: return "sha384";
    case algorithm instanceof Sha512: return "sha512";
    case algorithm instanceof Sha3224: return "sha3-224";
    case algorithm instanceof Sha3256: return "sha3-256";
    case algorithm instanceof Sha3384: return "sha3-384";
    case algorithm instanceof Sha3512: return "sha3-512";
    case algorithm instanceof Md5: return "md5";
    default: throw new Error("Unsupported algorithm");
  }
}

export function strongRandomBytes(n) {
  const array = new Uint8Array(n);
  webCrypto().getRandomValues(array);
  return new BitArray(array);
}

export function hmac(data, algorithm, key) {
  const hmac = crypto.createHmac(algorithmName(algorithm), key.buffer);
  hmac.update(data.buffer);
  const array = new Uint8Array(hmac.digest());
  return new BitArray(array);
}

export function hash(algorithm, data) {
  const hasher = crypto.createHash(algorithmName(algorithm));
  hasher.update(data.buffer);
  const array = new Uint8Array(hasher.digest());
  return new BitArray(array);
}
