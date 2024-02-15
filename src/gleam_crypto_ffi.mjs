import { BitArray } from "./gleam.mjs";
import { Sha224, Sha256, Sha384, Sha512 } from "./gleam/crypto.mjs";
import * as crypto from "node:crypto";

function webCrypto() {
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error("WebCrypto API not supported on this JavaScript runtime");
  }
  return globalThis.crypto;
}

function algorithmName(algorithm) {
  if (algorithm instanceof Sha224) {
    return "sha224";
  } else if (algorithm instanceof Sha256) {
    return "sha256";
  } else if (algorithm instanceof Sha384) {
    return "sha384";
  } else if (algorithm instanceof Sha512) {
    return "sha512";
  } else {
    throw new Error("Unsupported algorithm");
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
