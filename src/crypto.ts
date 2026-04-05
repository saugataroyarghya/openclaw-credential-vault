import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from "node:crypto";

import {
  ALGORITHM,
  IV_LENGTH,
  KEY_LENGTH,
  MASTER_KEY_ENV,
  SCRYPT_SALT,
} from "./constants.js";

let _derivedKey: Buffer | null = null;

export function getMasterKey(): Buffer {
  if (_derivedKey) return _derivedKey;

  const secret = process.env[MASTER_KEY_ENV];
  if (!secret || secret.length < 16) {
    throw new Error(
      `${MASTER_KEY_ENV} must be set to at least 16 characters.`,
    );
  }

  _derivedKey = scryptSync(secret, SCRYPT_SALT, KEY_LENGTH);
  return _derivedKey;
}

/** Reset cached key — only needed for testing. */
export function resetKeyCache(): void {
  _derivedKey = null;
}

export function encrypt(plaintext: string): {
  ciphertext: string;
  iv: string;
  authTag: string;
} {
  const key = getMasterKey();
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv);

  let encrypted = cipher.update(plaintext, "utf8", "hex");
  encrypted += cipher.final("hex");
  const authTag = cipher.getAuthTag().toString("hex");

  return {
    ciphertext: encrypted,
    iv: iv.toString("hex"),
    authTag,
  };
}

export function decrypt(
  ciphertext: string,
  iv: string,
  authTag: string,
): string {
  const key = getMasterKey();
  const decipher = createDecipheriv(
    ALGORITHM,
    key,
    Buffer.from(iv, "hex"),
  );
  decipher.setAuthTag(Buffer.from(authTag, "hex"));

  let decrypted = decipher.update(ciphertext, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}
