import { EmailSignupInput } from "./auth.schema.js";
import AuthRepository from "./auth.repo.js";
import { hashSecret, hashToken, compareSecret } from "@repo/auth-utils"
import { generateToken, generateAccessToken ,generateLoginToken } from "@repo/auth-utils"
import { EmailLoginInput } from "./auth.schema.js"
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


class AuthService {

    private createSession = async (user: User, input: SessionInput, logger: Logger) => {
        let token = generateToken();
        let hashedRefreshToken = hashToken(token);

        let session = await AuthRepository.createSession(
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


    async emailSignup(input: EmailSignupInput, logger: Logger) {
        logger.info("Starting email signup process for email: %s", input.email);
        let existingUser = await AuthRepository.checkUserExistsByEmail(input.email);
        if (existingUser) {
            logger.warn("Attempt to signup with existing email: %s", input.email);
            throw new ConflictError("Email already exists");
        }
        let hashedPassword = await hashSecret(input.password);
        const user = await AuthRepository.createUserWithAccount(
            { email: input.email, name: input.name },
            { provider: input.provider ?? "email", password: hashedPassword },
            logger
        );
        logger.info({ userId: user.id }, "user and account created");

        let { session, accessToken, refreshToken } = await this.createSession(user, input, logger);
        return ({ session, accessToken, refreshToken });
    }


    async emailLogin(input: EmailLoginInput, logger: Logger) {
        logger.info("Starting email login process for email: %s", input.email);
        const user = await AuthRepository.checkUserExistsByEmail(input.email);
        if (!user) {
            logger.warn("Login attempt with non-existent email: %s", input.email);
            throw new ConflictError("Invalid email or password");
        }
        const account = await AuthRepository.getAccount(user.id, "email");
        if (!account) {
            logger.warn("No email account found for user ID: %s", user.id);
            throw new ConflictError("Invalid email or password");
        }
        if (!account.password) {
            throw new ConflictError("This account uses a different login method");
        }

        const isPasswordValid = await compareSecret(input.password, account.password);
        if (!isPasswordValid) {
            logger.warn("Invalid password for user ID: %s", user.id);
            throw new ConflictError("Invalid email or password");
        }

        if(user.twoFactorEnabled===false){
            let { session, accessToken, refreshToken } = await this.createSession(user, input, logger);
            return ({requiresTwoFactor: false, session, accessToken, refreshToken });
        }

        const loginToken = generateLoginToken({ userId: user.id, type: "2fa_login" });
        return { requiresTwoFactor: true, loginToken , message: "Two-factor authentication is enabled. Please verify the 2FA token."};

    }


    
}


export default new AuthService();