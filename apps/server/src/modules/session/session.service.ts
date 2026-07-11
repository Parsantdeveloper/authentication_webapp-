import SessionRepository from "./session.repo.js";
import { generateToken, generateAccessToken,hashToken } from "@repo/auth-utils"
import type { Logger } from "../../config/logger.js";
import { ConflictError } from "@repo/errors";
import { Role } from "../../generated/prisma/browser.js";


interface User {
    email: string;
    name: string;
    id: string;
    phoneNumber: string | null;
    emailVerified: boolean;
    role: Role;
    createdAt: Date;
    updatedAt: Date;
}

interface SessionInput {
    device?: string;
    location?: string;
    user_agent?: string;
    ipAddress?: string;
}


class SessionService {



     createSession = async (user: User, input: SessionInput, logger: Logger) => {
        let token = generateToken();
        let hashedRefreshToken = hashToken(token);

        let session = await SessionRepository.createSession(
            {
                userId: user.id,
                token: hashedRefreshToken, // store hash, return raw to client
                device: input.device,
                location: input.location,
                user_agent: input.user_agent,
                ipAddress: input.ipAddress,
            },
            logger
        );

        let accessToken = generateAccessToken({
            id: user.id,
            email: user.email,
            name: user.name,
            role: user.role,
            sessionId: session.id
        })
        return { session, accessToken, refreshToken: token };
    }


   


    async logoutFromAllDevices(userId: string, logger: Logger) {
        return await SessionRepository.logoutFromAllDevices(userId, logger);
    }

    async getSession(sessionId: string, logger: Logger) {
        return await SessionRepository.getSession(sessionId, logger);
    }

    async refreshToken(refreshToken: string, logger: Logger) {
        const hashedtoken = hashToken(refreshToken);
        const session = await SessionRepository.getSessionByRefreshToken(hashedtoken, logger);
        if (!session) {
            logger.warn("Refresh token attempt with invalid session ID: %s", refreshToken);
            throw new ConflictError("Invalid session");
        }
        if (session.expiresAt < new Date()) {
            logger.warn("Refresh token attempt with expired session ID: %s", session.id);
            throw new ConflictError("Session expired");
        }

        const user = await SessionRepository.getUserById(session.userId);
        if (!user) {
            logger.warn("User not found for session ID: %s", session.id);
            throw new ConflictError("User not found");
        }
        const accessToken = generateAccessToken({
            id: session.userId,
            sessionId: session.id,
            email: user.email,
            name: user.name,
            role: user.role
        })
        return { accessToken };

    }

    async logoutFromDevice(sessionId: string, logger: Logger) {
        return await SessionRepository.logoutFromDevice(sessionId, logger);
    }

    


    
}


export default new SessionService();