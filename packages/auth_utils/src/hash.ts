import bcrypt from 'bcrypt';
import { AppError } from '@repo/errors';
import crypto from "crypto";

/**
 * Hashes a secret value (passwords, OTP codes) using bcrypt.
 *
 * Salted + slow by design. Two calls with the same input produce DIFFERENT
 * output, so this can never be used to look a record up by its hash - you
 * must already have the stored hash in hand and call compareSecret against it.
 *
 * Use for: passwords, OTP codes (email verification, password reset codes) -
 * anything where the caller also supplies an identifier (email, userId) you
 * can fetch the record by BEFORE comparing the secret.
 */
export const hashSecret = async (secret: string): Promise<string> => {
  try {
    const saltRounds = 10;
    return await bcrypt.hash(secret, saltRounds);
  } catch (error) {
    throw new AppError("Failed to hash secret", 500);
  }
};

export const compareSecret = async (secret: string, hash: string): Promise<boolean> => {
  try {
    return await bcrypt.compare(secret, hash);
  } catch (error) {
    throw new AppError("Failed to compare secret", 500);
  }
};

/**
 * Deterministic hash for bearer tokens (refresh tokens, magic link tokens).
 *
 * Same input ALWAYS produces the same output, so the hash itself can be used
 * as a direct database lookup key - unlike hashSecret/bcrypt above.
 *
 * Use for: any random opaque token where the token itself is the only thing
 * the client sends back (no separate identifier to look up by first).
 */
export const hashToken = (token: string): string => {
  try {
    return crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");
  } catch (error) {
    throw new AppError("Failed to hash token", 500);
  }
};

export function generateOTP(length: number = 6): string {
  const digits = "0123456789";
  const bytes = crypto.randomBytes(length);
  return Array.from(bytes)
    .map((byte) => digits[byte % 10])
    .join("");
}