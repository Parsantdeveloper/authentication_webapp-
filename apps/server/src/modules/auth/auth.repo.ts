
import prisma from "../../config/prisma.js";
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/client.js'
import {SessionCreateInput} from "./auth.schema.js";
import {EmailAlreadyExistsError} from "@repo/errors";
import { VerificationInput} from "./auth.type.js";
import type { Logger } from "../../config/logger.js";
import { VerificationType } from "../../generated/prisma/browser.js";
import { AppError } from "@repo/errors";

interface CreateUserData {
  email: string;
  name: string;
  emailVerified?: boolean;
}

interface CreateAccountData {
  provider: string;
  providerAccountId?: string;
  password?: string;
  accessToken?: string;
  refreshToken?: string;
  scope?: string;
  accessTokenExpiresAt?: Date;
  refreshTokenExpiresAt?: Date;
}

export class AuthRepository {

     async createUserWithAccount(
  userData: CreateUserData,
  accountData: CreateAccountData,
  logger: Logger
) {
  try {
    const user = await prisma.$transaction(async (tx) => {
      const newUser = await tx.user.create({
        data: {
          email: userData.email,
          name: userData.name,
          emailVerified: userData.emailVerified ?? false,
        },
      });

      logger.info(
        { userId: newUser.id },
        "User created with ID: %s",
        newUser.id
      );

      await tx.account.create({
        data: {
          userId: newUser.id,
          provider: accountData.provider,
          providerAccountId: accountData.providerAccountId,
          password: accountData.password,
          accessToken: accountData.accessToken,
          refreshToken: accountData.refreshToken,
          scope: accountData.scope,
          accessTokenExpiresAt: accountData.accessTokenExpiresAt,
          refreshTokenExpiresAt: accountData.refreshTokenExpiresAt,
        },
      });

      return newUser;
    });

    return user;
  } catch (error) {
    if (
      error instanceof PrismaClientKnownRequestError &&
      error.code === "P2002"
    ) {
      if (
        Array.isArray(error.meta?.target) &&
        error.meta.target.includes("email")
      ) {
        logger.warn(
          "Attempt to create user with existing email: %s",
          userData.email
        );
        throw new EmailAlreadyExistsError();
      }
    }

    logger.error(error, "Error creating user with account");
    throw error;
  }
}
   async createAccount(input: CreateAccountData & { userId: string },logger: Logger) {
  try {
    const account = await prisma.account.create({
      data: {
        userId: input.userId,
        provider: input.provider,
        providerAccountId: input.providerAccountId,
        password: input.password,
        accessToken: input.accessToken,
        refreshToken: input.refreshToken,
        scope: input.scope,
        accessTokenExpiresAt: input.accessTokenExpiresAt,
        refreshTokenExpiresAt: input.refreshTokenExpiresAt,
      },
    });

    return account;
  } catch (error) {
    if (
      error instanceof PrismaClientKnownRequestError &&
      error.code === "P2002"
    ) {
      logger.warn("Attempt to create account that already exists");
      throw new AppError(
        "Account already exists",
        409,
      );
    }

    throw error;
  }
}


    

        async createSession(sessionData: SessionCreateInput, logger: Logger) {
            try {
                logger.info("Creating session for user ID: %s", sessionData.userId);
                const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
                const session = await prisma.session.create({
                    data:{
                        ...sessionData,
                        expiresAt
                    }
                })
                logger.info("Session created with ID: %s for user ID: %s", session.id, session.userId);
                return session;
            } catch (error) {
                logger.error(error, "Error creating session");
                throw error;
            }
        }
        
    

      async checkUserExistsByEmail(email:string ){
          return await prisma.user.findUnique({
            where:{
                email:email
            }
          })
      }

      async logoutFromAllDevices(userId:string, logger: Logger) {
        try{
            let user=await prisma.session.deleteMany({
                where:{
                    userId:userId
                }
            })

            return user;
        }catch(error){
            logger.error(error, "Error logging out user from all devices");
            throw error;
        }
      }

      async getAccount(userId:string , provider:string){
        return await prisma.account.findUnique({
            where:{  
                userId_provider:{
                    userId:userId,
                    provider:provider
                }
            }
        })
      }

      async getSession(sessionId:string, logger: Logger){
        try{
            let session=await prisma.session.findUnique({
                where:{
                    id:sessionId
                },
                select:{
                    id:true , 
                    userId:true,
                    ipAddress:true,
                    device:true,
                    location:true,
                    // user_agent:true,
                    expiresAt:true
                }
               
            })
            return session;
        }catch(error){
            logger.error(error, "Error fetching session with ID: %s", sessionId);
            throw error;
        }
      }
    
      async getSessionByRefreshToken(refreshToken:string, logger: Logger){
        try{
            let session=await prisma.session.findFirst({
                where:{
                    token:refreshToken}})

                 return session;   

                }catch(error){
                    logger.error(error, "Error fetching session with refresh token");
                    throw error;
                }
      }

      async getUserById(userId:string){
        return await prisma.user.findUnique({
            where:{
                id:userId
            }
        })
      }

      async logoutFromDevice(sessionId:string,logger:Logger){
         try{
            let session = await prisma.session.delete({
                where:{
                    id:sessionId
                }
            })
            logger.info("Session with ID: %s logged out successfully", sessionId);
            return session;
         }catch(error){
            logger.error(error, "Error logging out session with ID: %s", sessionId);
            throw error;
                }
            }

    async createVerification( input: VerificationInput, logger: Logger){
        try{
            const verification = await prisma.verification.create({
                data:{
                    identifier:input.identifier,
                    tokenHash:input.tokenHash,
                    type:input.type,
                    expiresAt:input.expiresAt
                }
            })
            logger.info("Verification code created for email: %s", input.identifier);
            return verification;
        }catch(error){
            logger.error(error, "Error creating verification code for email: %s", input.identifier);
            throw error;
        }
    }  
    
    async getVerificationByIdentifier(identifier:string, type:VerificationType, logger:Logger){
        try{
            const verification = await prisma.verification.findFirst({
                where:{
                    identifier:identifier,
                    usedAt:null,
                    expiresAt:{
                        gt:new Date()
                    },
                    type:type
                }
            })
            if(!verification){
                logger.warn("No verification code found for identifier: %s", identifier);
            }else{
                logger.info("Verification code retrieved for identifier: %s", identifier);
            }
            return verification;
        }catch(error){
            logger.error(error, "Error retrieving verification code for identifier: %s", identifier);
            throw error;
        }
    }
    
     async getVerificationByHashedToken(hashedToken:string, type:VerificationType, logger:Logger){
        try{
            const verification = await prisma.verification.findFirst({
                where:{
                    tokenHash:hashedToken,
                    usedAt:null,
                    expiresAt:{
                        gt:new Date()
                    },
                    type:type
                }
            })
            if(!verification){
                logger.warn("No verification code found for hashed token: %s");
            }else{
                logger.info("Verification code retrieved for hashed token: %s");
            }
            return verification;
        }catch(error){
            logger.error(error, "Error retrieving verification code for hashed token: %s");
            throw error;
        }
    }

    

         
    async markVerificationAsUsed(verificationId:string, logger:Logger){
        try{
            const verification = await prisma.verification.update({
                where:{
                    id:verificationId
                },
                data:{
                    usedAt:new Date()
                }
            })
            logger.info("Verification code with ID: %s marked as used", verificationId);
            return verification;
        }catch(error){
            logger.error(error, "Error marking verification code with ID: %s as used", verificationId);
            throw error;
        }
    }
    
    async verifyEmail(email:string,logger:Logger){

        try{
          const user = await prisma.user.update({
            where:{
                email:email
            },
            data:{
                emailVerified:true
            }
          })
          return user;
        }catch(error){
            logger.error(error, "Error verifying email for user: %s", email);
            throw error;
        }

    }

    async changePassword(id:string , password:string){
         try{
          const user = await prisma.account.update({
            where:{
               id
            },
            data:{
                password
            }
          })
          return user
         }catch(error){
            throw new AppError("Failed to change password for account ID: " + id, 500);
         }
    }

    async addTwoFactorSecret(email:string,secret:string,logger:Logger){
        try{
         const user  = await prisma.user.update({
            where:{
                email:email
            },
            data:{
                twoFactorSecret:secret
            }
         })
         logger.info("Two-factor secret added for user ID: %s", email);
         return user ; 
        }catch(error){
            logger.error(error, "Error adding two-factor secret for user ID: %s", email);
            throw error;
        }
    }
}


export default new AuthRepository();