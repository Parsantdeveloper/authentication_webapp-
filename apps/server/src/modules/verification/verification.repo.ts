
import prisma from "../../config/prisma.js";
import { VerificationInput } from "./verification.type.js";
import {  type Logger } from "../../config/logger.js";
import { VerificationType } from "../../generated/prisma/browser.js";
import { AppError } from "@repo/errors";



export class VerificationRepository {



    async createVerification(input: VerificationInput, logger: Logger) {
        try {
            const verification = await prisma.verification.create({
                data: {
                    identifier: input.identifier,
                    tokenHash: input.tokenHash,
                    type: input.type,
                    expiresAt: input.expiresAt
                }
            })
            logger.info("Verification code created for email: %s", input.identifier);
            return verification;
        } catch (error) {
            logger.error(error, "Error creating verification code for email: %s", input.identifier);
            throw error;
        }
    }

    async getVerificationByIdentifier(identifier: string, type: VerificationType, logger: Logger) {
        try {
            const verification = await prisma.verification.findFirst({
                where: {
                    identifier: identifier,
                    usedAt: null,
                    expiresAt: {
                        gt: new Date()
                    },
                    type: type
                }
            })
            if (!verification) {
                logger.warn("No verification code found for identifier: %s", identifier);
            } else {
                logger.info("Verification code retrieved for identifier: %s", identifier);
            }
            return verification;
        } catch (error) {
            logger.error(error, "Error retrieving verification code for identifier: %s", identifier);
            throw error;
        }
    }

    async getVerificationByHashedToken(hashedToken: string, type: VerificationType, logger: Logger) {
        try {
            const verification = await prisma.verification.findFirst({
                where: {
                    tokenHash: hashedToken,
                    usedAt: null,
                    expiresAt: {
                        gt: new Date()
                    },
                    type: type
                }
            })
            if (!verification) {
                logger.warn("No verification code found for hashed token: %s");
            } else {
                logger.info("Verification code retrieved for hashed token: %s");
            }
            return verification;
        } catch (error) {
            logger.error(error, "Error retrieving verification code for hashed token: %s");
            throw error;
        }
    }




    async markVerificationAsUsed(verificationId: string, logger: Logger) {
        try {
            const verification = await prisma.verification.update({
                where: {
                    id: verificationId
                },
                data: {
                    usedAt: new Date()
                }
            })
            logger.info("Verification code with ID: %s marked as used", verificationId);
            return verification;
        } catch (error) {
            logger.error(error, "Error marking verification code with ID: %s as used", verificationId);
            throw error;
        }
    }

    async verifyEmail(email: string, logger: Logger) {

        try {
            const user = await prisma.user.update({
                where: {
                    email: email
                },
                data: {
                    emailVerified: true
                }
            })
            return user;
        } catch (error) {
            logger.error(error, "Error verifying email for user: %s", email);
            throw error;
        }

    }

    async changePassword(id: string, password: string) {
        try {
            const user = await prisma.account.update({
                where: {
                    id
                },
                data: {
                    password
                }
            })
            return user
        } catch (error) {
            throw new AppError("Failed to change password for account ID: " + id, 500);
        }
    }

    async addTwoFactorSecret(email: string, secret: string, logger: Logger) {
        try {
            const user = await prisma.user.update({
                where: {
                    email: email
                },
                data: {
                    twoFactorSecret: secret
                }
            })
            logger.info("Two-factor secret added for user ID: %s", email);
            return user;
        } catch (error) {
            logger.error(error, "Error adding two-factor secret for user ID: %s", email);
            throw error;
        }
    }


    async getTwoFactorSecret(email: string, logger: Logger) {
        try {
            const user = await prisma.user.findUnique({
                where: {
                    email: email
                },
                select: {
                    twoFactorSecret: true
                }
            })
            if (!user) {
                logger.warn("User not found for email: %s", email);
                throw new AppError("User not found", 404);
            }
            logger.info("Two-factor secret retrieved for user ID: %s", email);
            return user.twoFactorSecret;
        } catch (error) {
            logger.error(error, "Error retrieving two-factor secret for user ID: %s", email);
            throw error;
        }
    }

    async enableTwoFactorAuth(email: string, logger: Logger) {
        try {
            const user = await prisma.user.update({
                where: {
                    email: email
                },
                data: {
                    twoFactorEnabled: true
                }
            })
            logger.info("Two-factor authentication enabled for user ID: %s", email);
            return user;
        } catch (error) {
            logger.error(error, "Error enabling two-factor authentication for user ID: %s", email);
            throw error;
        }

    }

    async disableTwoFactorAuth(email: string, logger: Logger) {
        try {
            const user = await prisma.user.update({
                where: {
                    email: email
                },
                data: {
                    twoFactorEnabled: false,
                    twoFactorSecret: null
                }
            })
            logger.info("Two-factor authentication disabled for user ID: %s", email);
            return user;
        } catch (error) {
            logger.error(error, "Error disabling two-factor authentication for user ID: %s", email);
            throw error;
        }
    }

    async addRecoveryCodes(userId:string,hashedRecoveryCodes:string[],logger:Logger){
        try {
            const recoveryCodes = await prisma.recoveryCode.createMany({
                data: hashedRecoveryCodes.map(code => ({
                    userId: userId,
                    code,
                }))
            })
            logger.info("Recovery codes added for user ID: %s", userId);
            return recoveryCodes;
        } catch (error) {
            logger.error(error, "Error adding recovery codes for user ID: %s", userId);
            throw error;
        }
    }

    async deleteRecoveryCodes(userId:string,logger:Logger){
        try {
            const recoveryCodes = await prisma.recoveryCode.deleteMany({
                where: {
                    userId: userId
                }
            })
            logger.info("Recovery codes deleted for user ID: %s", userId);
            return recoveryCodes;
        } catch (error) {
            logger.error(error, "Error deleting recovery codes for user ID: %s", userId);
            throw error;
        }
    }

    async getRecoveryCode(hashedCode:string,userId:string,logger:Logger){
        try {
            const recoveryCode = await prisma.recoveryCode.findFirst({
                where: {
                    code: hashedCode,
                    userId: userId,
                    used: false,
                  
                }
            })
            console.log("Recovery code retrieved for hashed code: %s", recoveryCode);
            if (!recoveryCode) {
                logger.warn("No recovery code found for hashed code: %s", hashedCode);
            } else {
                logger.info("Recovery code retrieved for hashed code: %s", hashedCode);
            }
            return recoveryCode;
        } catch (error) {
            logger.error(error, "Error retrieving recovery code for hashed code: %s", hashedCode);
            throw error;
        }
    }


}

export default new VerificationRepository();