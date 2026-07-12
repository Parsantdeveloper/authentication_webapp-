import crypto from "crypto";
import jwt from "jsonwebtoken";
import { env } from "@repo/config";
import * as OTPAuth from "otpauth";
import Cryptr from "cryptr";
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

export const generateLoginToken=(input:{userId:string,type:"2fa_login"})=>{
   return jwt.sign(input, ACCESS_TOKEN_SECRET, { expiresIn: "5m" });
}

export const verifyLoginToken=(token:string)=>{
    try {
        return jwt.verify(token, ACCESS_TOKEN_SECRET) as {userId:string,type:"2fa_login"};
      } catch (error) {
        throw new Error("Invalid or expired token");
      }
}
/**
 * Generates a random opaque bearer token (64 bytes, hex-encoded).
 * Used for refresh tokens AND magic link tokens - always paired with
 * hashToken() from hash.utils for storage/lookup. Renamed from
 * generateRefreshToken since it's no longer refresh-token-specific.
 */
export const generateToken = (): string => {
  return crypto.randomBytes(64).toString("hex");
};

export const generatePasswordResetToken = (payload: { userId: string; purpose: string }): string => {
  return jwt.sign(payload, ACCESS_TOKEN_SECRET, { expiresIn: "10m" });
};

export const verifyPasswordResetToken = (token: string): { userId: string; purpose: string } => {
  try {
    return jwt.verify(token, ACCESS_TOKEN_SECRET) as { userId: string; purpose: string };
  } catch (error) {
    throw new Error("Invalid or expired token");
  }
};



const cryptr = new Cryptr(process.env.TOTP_SECRET_KEY!);


 export function encryptSecret(secret: string): string {
  return cryptr.encrypt(secret);
}

 export function decryptSecret(encryptedSecret: string): string {
  return cryptr.decrypt(encryptedSecret);

}

export  function generateSecret(){
const secret = new OTPAuth.Secret(); 
return secret;
}

export function generateTOTP(email:string,secret:any){
    try{
    const totp = new OTPAuth.TOTP({
    issuer: "MyAuthService",
    label: email,
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    secret,
});
        return totp;

    }catch(error){
        throw new Error("Failed to generate TOTP");
    }
}
