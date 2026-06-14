
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { env } from "@repo/config";

const ACCESS_TOKEN_SECRET = env.JWT_SECRET;

interface JwtPayload {
  id: string;
  sessionId?: string;
  email: string;
  name: string;
  role: string;
}

export const generateAccessToken = (
  payload: JwtPayload
): string => {
  return jwt.sign(
    payload,
    ACCESS_TOKEN_SECRET,
    {
      expiresIn: "15m",
    }
  );
};

export const verifyAccessToken = (
  token: string
) => {
  try {
    return jwt.verify(token, ACCESS_TOKEN_SECRET) as JwtPayload;
  } catch (error) {
    throw new Error("Invalid or expired token");
  }
};

export const generateRefreshToken = (): string => {
  return crypto.randomBytes(64).toString("hex");
};