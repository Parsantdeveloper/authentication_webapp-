
import prisma from "../../config/prisma.js";
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/client.js'
import {SessionCreateInput} from "./auth.schema.js";
import {EmailAlreadyExistsError} from "@repo/errors";
import type { Logger } from "../../config/logger.js";

export class AuthRepository {

     async createUserWithAccount(userData: { email: string; name: string }, accountData: { provider: string; password: string }, logger: Logger) {
         try {
           const user = await prisma.$transaction(async(tx)=>{
             const newUser = await tx.user.create({
                data:{
                    email:userData.email,
                    name:userData.name

                }
             })
                logger.info({ userId: newUser.id }, "User created with ID: %s", newUser.id);
                await tx.account.create({
                    data:{
                        userId:newUser.id,
                        provider:accountData.provider,
                        password:accountData.password
                    }
                })
                return newUser
           })
           return user;
         } catch (error) {
            if(error instanceof PrismaClientKnownRequestError && error.code ==="P2002"){
                if(Array.isArray(error.meta?.target) && error.meta.target.includes("email")){
                    logger.warn("Attempt to create user with existing email: %s", userData.email);
                    throw new EmailAlreadyExistsError();
                }
            }
             logger.error(error, "Error creating user with account");
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
                    user_agent:true,
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
      
}

export default new AuthRepository();