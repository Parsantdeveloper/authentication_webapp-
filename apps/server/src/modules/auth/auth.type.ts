
import { VerificationType } from "../../generated/prisma/enums.js";


export interface VerificationInput {
  identifier: string;
  tokenHash: string;
  type:VerificationType,
  expiresAt: Date;
}


export interface VerifyCode{
   code:string;
   identifier:string;
  type:VerificationType;
}