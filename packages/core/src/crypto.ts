import { createCipheriv, createDecipheriv, randomBytes, createHash } from "node:crypto";

function derive32(keyMaterial: string): Buffer {
  return createHash("sha256").update(keyMaterial).digest();
}

export function encryptString(plaintext: string, keyMaterial: string): string {
  const key = derive32(keyMaterial);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString("base64");
}

export function decryptString(ciphertext: string, keyMaterial: string): string {
  const key = derive32(keyMaterial);
  const payload = Buffer.from(ciphertext, "base64");
  const iv = payload.subarray(0, 12);
  const tag = payload.subarray(12, 28);
  const encrypted = payload.subarray(28);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return decrypted.toString("utf8");
}
