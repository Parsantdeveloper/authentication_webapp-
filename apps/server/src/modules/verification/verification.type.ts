
import { VerificationType } from "../../generated/prisma/enums.js";


export interface VerificationInput {
  identifier: string;
  tokenHash: string;
  type:VerificationType,
  expiresAt: Date;
}


export interface VerifyCode{
   userId:string;
   code:string;
   identifier:string;
  type:VerificationType;
}

export interface changePasswordTypes{
   email:string 
   old_password:string
   new_password:string
   user_id:string
}

export interface SessionInput {
    device?: string;
    location?: string;
    user_agent?: string;
    ipAddress?: string;
}