
import crypto from "crypto";
import jwt from "jsonwebtoken";
import {env} from "@repo/config";

const ACCESS_TOKEN_SECRET = env.JWT_SECRET;


export const generateAccessToken = (
  userId: string
): string => {
  return jwt.sign(
    { userId },
    ACCESS_TOKEN_SECRET,
    {
      expiresIn: "15m",
    }
  );
};

export const verifyAccessToken = (
  token: string
) => {
  return jwt.verify(
    token,
    ACCESS_TOKEN_SECRET
  );
};

export const generateRefreshToken = (): string => {
  return crypto.randomBytes(64).toString("hex");
};