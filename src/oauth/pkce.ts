import { randomBytes, createHash } from "node:crypto";

function base64url(buffer: Buffer): string {
  return buffer.toString("base64url");
}

export function generatePkce(): { verifier: string; challenge: string } {
  const verifier = base64url(randomBytes(32));
  const challenge = base64url(createHash("sha256").update(verifier).digest());
  return { verifier, challenge };
}
