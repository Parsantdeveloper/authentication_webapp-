
import prisma from "../../config/prisma.js";
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/client.js'
import { SessionCreateInput } from "./auth.schema.js";
import { EmailAlreadyExistsError } from "@repo/errors";
import {  type Logger } from "../../config/logger.js";
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
    async createAccount(input: CreateAccountData & { userId: string }, logger: Logger) {
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
                data: {
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



    async checkUserExistsByEmail(email: string) {
        return await prisma.user.findUnique({
            where: {
                email: email
            }
        })
    }

    async logoutFromAllDevices(userId: string, logger: Logger) {
        try {
            let user = await prisma.session.deleteMany({
                where: {
                    userId: userId
                }
            })

            return user;
        } catch (error) {
            logger.error(error, "Error logging out user from all devices");
            throw error;
        }
    }

    async getAccount(userId: string, provider: string) {
        return await prisma.account.findUnique({
            where: {
                userId_provider: {
                    userId: userId,
                    provider: provider
                }
            }
        })
    }

   async getUserById(userId: string) {
        return await prisma.user.findUnique({
            where: {
                id: userId
            }
        })
    }



    
}

export default new AuthRepository();