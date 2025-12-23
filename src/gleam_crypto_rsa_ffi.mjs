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
import { Pkcs1v15, Pss, Pkcs1, Pkcs8 } from "./gleam/crypto/rsa.mjs";
import * as crypto from "node:crypto";

// Standard RSA public exponent
const RSA_PUBLIC_EXPONENT = 65537;

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

// --- Key Generation ---

export function generateKeyPair(bits) {
  try {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: bits,
      publicExponent: RSA_PUBLIC_EXPONENT,
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
      type: fmt === "pem" ? undefined : "pkcs1",
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
      type: fmt === "pem" ? undefined : "pkcs1",
    });
    return new Ok(key);
  } catch (e) {
    if (format instanceof Der) {
      try {
        const key = crypto.createPublicKey({
          key: data.rawBuffer,
          format: "der",
          type: "spki",
        });
        return new Ok(key);
      } catch (e2) {
        return new ResultError(undefined);
      }
    }
    return new ResultError(undefined);
  }
}

// --- Key Export ---

export function privateKeyToBytes(key, format, keyFormat) {
  const fmt = formatName(format);
  const type = keyFormat instanceof Pkcs1 ? "pkcs1" : "pkcs8";
  const exported = key.export({
    format: fmt,
    type: type,
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
    type: "pkcs1",
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

export function sign(key, message, hash, padding) {
  const algo = algorithmName(hash);
  const paddingValue =
    padding instanceof Pss
      ? crypto.constants.RSA_PKCS1_PSS_PADDING
      : crypto.constants.RSA_PKCS1_PADDING;

  const options = {
    key: key,
    padding: paddingValue,
  };

  if (padding instanceof Pss) {
    options.saltLength = crypto.constants.RSA_PSS_SALTLEN_DIGEST;
  }

  const signature = crypto.sign(algo, message.rawBuffer, options);
  return new BitArray(new Uint8Array(signature));
}

export function verify(key, message, signature, hash, padding) {
  const algo = algorithmName(hash);
  const paddingValue =
    padding instanceof Pss
      ? crypto.constants.RSA_PKCS1_PSS_PADDING
      : crypto.constants.RSA_PKCS1_PADDING;

  const options = {
    key: key,
    padding: paddingValue,
  };

  if (padding instanceof Pss) {
    options.saltLength = crypto.constants.RSA_PSS_SALTLEN_DIGEST;
  }

  try {
    return crypto.verify(algo, message.rawBuffer, options, signature.rawBuffer);
  } catch (e) {
    return false;
  }
}
