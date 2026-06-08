import { EmailSignupInput } from "./auth.schema.js";
import AuthRepository from "./auth.repo.js";
import { hashPassword, hashRefreshToken } from "@repo/auth-utils"
import { generateRefreshToken,generateAccessToken } from "@repo/auth-utils"
import type { Logger } from "../../config/logger.js";
import { ConflictError } from "@repo/errors";
class AuthService {



    async emailSignup(input: EmailSignupInput, logger: Logger) {
        logger.info("Starting email signup process for email: %s", input.email);
        let existingUser = await AuthRepository.checkUserExistsByEmail(input.email);
         if(existingUser){
            logger.warn("Attempt to signup with existing email: %s", input.email);
            throw new ConflictError("Email already exists");
         }
        let hashedPassword = await hashPassword(input.password);
        const user = await AuthRepository.createUserWithAccount(
            { email: input.email, name: input.name },
            { provider: input.provider ?? "email", password: hashedPassword },
            logger
        );
        logger.info({ userId: user.id }, "user and account created");

        let token = generateRefreshToken();
        let hashedRefreshToken = await hashRefreshToken(token);

        await AuthRepository.createSession(
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
         
        let accessToken = generateAccessToken(user.id);

        return ({ accessToken: accessToken, refreshToken: token });
    }


}


export default new AuthService()