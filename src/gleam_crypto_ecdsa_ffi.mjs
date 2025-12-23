import { BitArray, Ok, Error as ResultError } from "./gleam.mjs";
import {
  Sha1,
  Sha224,
  Sha256,
  Sha384,
  Sha512,
  Md5,
  Pem,
  Der,
} from "./gleam/crypto.mjs";
import { P256, P384, P521 } from "./gleam/crypto/ecdsa.mjs";
import * as crypto from "node:crypto";

function algorithmName(algorithm) {
  if (algorithm instanceof Sha1) {
    return "sha1";
  } else if (algorithm instanceof Sha224) {
    return "sha224";
  } else if (algorithm instanceof Sha256) {
    return "sha256";
  } else if (algorithm instanceof Sha384) {
    return "sha384";
  } else if (algorithm instanceof Sha512) {
    return "sha512";
  } else if (algorithm instanceof Md5) {
    return "md5";
  } else {
    throw new Error("Unsupported algorithm");
  }
}

function formatName(format) {
  if (format instanceof Pem) {
    return "pem";
  } else if (format instanceof Der) {
    return "der";
  } else {
    throw new Error("Unsupported format");
  }
}

function curveName(curve) {
  if (curve instanceof P256) {
    return "prime256v1";
  } else if (curve instanceof P384) {
    return "secp384r1";
  } else if (curve instanceof P521) {
    return "secp521r1";
  } else {
    throw new Error("Unsupported curve");
  }
}

// --- Key Generation ---

export function generateKeyPair(curve) {
  try {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
      namedCurve: curveName(curve),
    });
    return new Ok([privateKey, publicKey]);
  } catch (e) {
    return new ResultError(undefined);
  }
}

// --- Key Import ---

export function privateKey(data, format) {
  try {
    const fmt = formatName(format);
    const key = crypto.createPrivateKey({
      key: data.rawBuffer,
      format: fmt,
      type: fmt === "pem" ? undefined : "sec1",
    });
    return new Ok(key);
  } catch (e) {
    // Try PKCS8 format for DER
    if (format instanceof Der) {
      try {
        const key = crypto.createPrivateKey({
          key: data.rawBuffer,
          format: "der",
          type: "pkcs8",
        });
        return new Ok(key);
      } catch (e2) {
        return new ResultError(undefined);
      }
    }
    return new ResultError(undefined);
  }
}

export function publicKey(data, format) {
  try {
    const fmt = formatName(format);
    const key = crypto.createPublicKey({
      key: data.rawBuffer,
      format: fmt,
      type: fmt === "pem" ? undefined : "spki",
    });
    return new Ok(key);
  } catch (e) {
    return new ResultError(undefined);
  }
}

// --- Key Export ---

export function privateKeyToBytes(key, format) {
  const fmt = formatName(format);
  const exported = key.export({
    format: fmt,
    type: "sec1",
  });
  if (fmt === "pem") {
    return new BitArray(new Uint8Array(Buffer.from(exported)));
  }
  return new BitArray(new Uint8Array(exported));
}

export function publicKeyToBytes(key, format) {
  const fmt = formatName(format);
  const exported = key.export({
    format: fmt,
    type: "spki",
  });
  if (fmt === "pem") {
    return new BitArray(new Uint8Array(Buffer.from(exported)));
  }
  return new BitArray(new Uint8Array(exported));
}

// --- Public Key Derivation ---

export function publicKeyFromPrivate(privateKey) {
  return crypto.createPublicKey(privateKey);
}

// --- Sign/Verify ---

export function sign(key, message, hash) {
  const algo = algorithmName(hash);
  const signature = crypto.sign(algo, message.rawBuffer, key);
  return new BitArray(new Uint8Array(signature));
}

export function verify(key, message, signature, hash) {
  const algo = algorithmName(hash);
  try {
    return crypto.verify(algo, message.rawBuffer, key, signature.rawBuffer);
  } catch (e) {
    return false;
  }
}
