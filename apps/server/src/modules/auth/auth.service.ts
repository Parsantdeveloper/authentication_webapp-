import { EmailSignupInput } from "./auth.schema.js";
import AuthRepository from "./auth.repo.js";
import { hashSecret, hashToken, compareSecret, generateOTP } from "@repo/auth-utils"
import { generateToken, generateAccessToken, generatePasswordResetToken, verifyPasswordResetToken } from "@repo/auth-utils"
import { EmailLoginInput } from "./auth.schema.js"
import { decryptSecret, encryptSecret, generateSecret, generateTOTP } from "../../libs/totp.auth.js"
import emailQueue from "../../libs/email.subscriber.js"
import type { Logger } from "../../config/logger.js";
import { ConflictError, AppError } from "@repo/errors";
import { VerifyCode, changePasswordTypes } from "./auth.type.js";
import { Role } from "../../generated/prisma/browser.js";
import QRCode from "qrcode";


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

        let { session, accessToken, refreshToken } = await this.createSession(user, input, logger);
        return ({ session, accessToken, refreshToken });

    }



    async logoutFromAllDevices(userId: string, logger: Logger) {
        return await AuthRepository.logoutFromAllDevices(userId, logger);
    }

    async getSession(sessionId: string, logger: Logger) {
        return await AuthRepository.getSession(sessionId, logger);
    }

    async refreshToken(refreshToken: string, logger: Logger) {
        const hashedtoken = hashToken(refreshToken);
        const session = await AuthRepository.getSessionByRefreshToken(hashedtoken, logger);
        if (!session) {
            logger.warn("Refresh token attempt with invalid session ID: %s", refreshToken);
            throw new ConflictError("Invalid session");
        }
        if (session.expiresAt < new Date()) {
            logger.warn("Refresh token attempt with expired session ID: %s", session.id);
            throw new ConflictError("Session expired");
        }

        const user = await AuthRepository.getUserById(session.userId);
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
        return await AuthRepository.logoutFromDevice(sessionId, logger);
    }

    async sendEmailVerification(email: string, logger: Logger) {
        const code = generateOTP(6);
        const hashedCode = await hashSecret(code);
        const verification_exist = await AuthRepository.getVerificationByIdentifier(email, "EMAIL_VERIFICATION", logger);
        if (verification_exist) {
            logger.info("Existing verification code found for email: %s", email);
            throw new ConflictError("Verification code already sent. Please check your email. or wait for the previous code to expire.");
        }
        const verification = await AuthRepository.createVerification({
            identifier: email,
            tokenHash: hashedCode,
            type: "EMAIL_VERIFICATION",
            expiresAt: new Date(Date.now() + 1 * 60 * 1000)
        }, logger)
        if (verification) {
            await emailQueue.add("email_verification", {
                type: "email_verification",
                to: email,
                name: email,
                otp: code, // raw OTP goes to email only, never stored
            });

            logger.info(`Email queued successfully, email:${email}`);

            return verification;

        }

    }


    async verifyEmail(input: VerifyCode, logger: Logger) {

        const verification = await AuthRepository.getVerificationByIdentifier(input.identifier, input.type, logger);
        const isValid = await compareSecret(input.code, verification?.tokenHash ?? "");
        if (!verification || !isValid) {
            logger.warn("Invalid verification attempt for identifier: %s", input.identifier);
            throw new ConflictError("Invalid verification code");
        }
        const user = await AuthRepository.verifyEmail(input.identifier, logger);
        await AuthRepository.markVerificationAsUsed(verification.id, logger);
        return user;
    }


    async passwordChange(input: changePasswordTypes) {
        let account = await AuthRepository.getAccount(input.user_id, "email")
        if (!account) {
            throw new ConflictError("User doesnot exists");
        }
        let isOldPasswordValid = await compareSecret(input.old_password, account.password ?? "");
        if (!isOldPasswordValid) {
            throw new ConflictError("Old password is incorrect");
        }
        if (input.old_password === input.new_password) {
            throw new ConflictError("Old password and new password cannot be same.");
        }

        let newHashedPassword = await hashSecret(input.new_password);
        try {
            await AuthRepository.changePassword(account.id, newHashedPassword);
            return { message: "Password changed successfully" };
        } catch (error) {
            throw new ConflictError("Failed to change password");
        }
    }


    async forgetPassword(email: string, logger: Logger) {
        const user = await AuthRepository.checkUserExistsByEmail(email);
        if (!user) {
            throw new ConflictError("User doesnot exists");
        }
        const code = generateOTP(6);
        const hashedCode = await hashSecret(code);

        const verification_exist = await AuthRepository.getVerificationByIdentifier(email, "PASSWORD_RESET", logger);
        if (verification_exist) {
            logger.info("Existing password reset code found for email: %s", email);
            throw new ConflictError("Password reset code already sent. Please check your email. or wait for the previous code to expire.");
        }
        const verification = await AuthRepository.createVerification({
            identifier: email,
            tokenHash: hashedCode,
            type: "PASSWORD_RESET",
            expiresAt: new Date(Date.now() + 1 * 60 * 1000)
        }, logger)
        if (verification) {

            await emailQueue.add("password_reset", {
                type: "password_reset",
                to: email,
                name: user.name,
                otp: code, // raw OTP goes to email only, never stored
            });

            logger.info(`Password reset email queued successfully, email:${email}`);
            return { message: "Password reset email sent successfully" };
        }
    }

    async verifyPasswordResetToken(input: VerifyCode, logger: Logger) {

        const verification = await AuthRepository.getVerificationByIdentifier(input.identifier, "PASSWORD_RESET", logger);
        const isValid = await compareSecret(input.code, verification?.tokenHash ?? "");
        if (!verification || !isValid) {
            logger.warn("Invalid verification attempt for identifier: %s", input.identifier);
            throw new ConflictError("Invalid verification code");
        }

        const reset_token = generatePasswordResetToken({ userId: input.userId, purpose: "PASSWORD_RESET" });
        await AuthRepository.markVerificationAsUsed(verification.id, logger);
        return reset_token;
    }

    async changePasswordWithResetToken(token: string, new_password: string, logger: Logger) {
        const payload = verifyPasswordResetToken(token);
        if (!payload || payload.purpose !== "PASSWORD_RESET") {
            throw new ConflictError("Invalid or expired password reset token");
        }
        const account = await AuthRepository.getAccount(payload.userId, "email");
        if (!account) {
            throw new ConflictError("User doesnot exists");
        }
        let newHashedPassword = await hashSecret(new_password);

        try {
            await AuthRepository.changePassword(account.id, newHashedPassword);
            return { message: "Password changed successfully" };
        } catch {
            throw new ConflictError("Failed to change password");
        }
    }

    async magicLinkRequest(email: string, logger: Logger) {
        const token = generateToken();
        // Deterministic hash - lets magicLinkLogin look this row up directly
        // by re-hashing the token the user clicks through with, with no
        // email/identifier available at that point.
        const tokenHash = hashToken(token);
        const verification_exist = await AuthRepository.getVerificationByIdentifier(email, "MAGIC_LINK", logger);
        if (verification_exist) {
            logger.info("Existing magic link found for email: %s", email);
            throw new ConflictError("Magic link already sent. Please check your email. or wait for the previous link to expire.");
        }
        const verification = await AuthRepository.createVerification({
            identifier: email,
            tokenHash: tokenHash,
            type: "MAGIC_LINK",
            expiresAt: new Date(Date.now() + 10 * 60 * 1000) // 10 minute expiration
        }, logger)

        if (!verification) {
            throw new AppError("Failed to create magic link verification", 500);
        }

        try {
            const job = await emailQueue.add("magic_link", {
                type: "magic_link",
                to: email,
                name: email,
                otp: token, // raw token goes to email only, never stored
            });

            logger.info(`Queued email job ${job.id}`);
            return { message: "Magic link email sent successfully" };
        } catch (err) {
            logger.error(err);
            throw new AppError("Failed to queue email", 500);
        }


    }

    async magicLinkLogin(token: string, sessionInput: SessionInput, logger: Logger) {
        const tokenHash = hashToken(token);
        const verification = await AuthRepository.getVerificationByHashedToken(tokenHash, "MAGIC_LINK", logger);
        if (!verification) {
            throw new ConflictError("Invalid or expired magic link");
        }

        let user = await AuthRepository.checkUserExistsByEmail(verification.identifier);

        if (!user) {
            // No user at all yet -> create user + magic_link account together
            user = await AuthRepository.createUserWithAccount(
                { email: verification.identifier, name: verification.identifier, emailVerified: true },
                { provider: "magic_link", providerAccountId: verification.identifier },
                logger
            );
            logger.info({ userId: user.id }, "user and magic_link account created");
        } else {
            // User exists (maybe signed up with email/password before) but
            // may not have a magic_link account linked yet -> link it.
            const account = await AuthRepository.getAccount(user.id, "magic_link");
            if (!account) {
                await AuthRepository.createAccount(
                    { provider: "magic_link", providerAccountId: verification.identifier, userId: user.id },
                    logger
                );
                logger.info({ userId: user.id }, "magic_link account linked to existing user");
            }
            // else: user + account both already exist, nothing to create -
            // fall straight through to issuing a session below.
        }

        await AuthRepository.markVerificationAsUsed(verification.id, logger);

        let { session, accessToken, refreshToken } = await this.createSession(user, sessionInput, logger);
        return ({ session, accessToken, refreshToken });
    }


    async setup2fa(email: string, logger: Logger) {
         const user = await AuthRepository.checkUserExistsByEmail(email);
        if (!user) {
            throw new ConflictError("User doesnot exists");
        }
        if(user.twoFactorEnabled===true){
        throw new ConflictError("Two-factor authentication is already enabled.");

        }
        const secret = generateSecret();
        const totp = generateTOTP(email, secret);
        const encryptedSecret = encryptSecret(secret.base32);
        const twoFactorSecret = await AuthRepository.addTwoFactorSecret(email, encryptedSecret, logger);
        if (!twoFactorSecret) {
            throw new ConflictError("Failed to setup two factor authentication");
        }
        const url = totp.toString();
        const qrCode = await QRCode.toDataURL(url);
        return { qrCode };
    }

    async verify2fa(input: { email: string; token: string }, logger: Logger) {
        const encryptedSecret = await AuthRepository.getTwoFactorSecret(input.email, logger);
        if (!encryptedSecret) {
            throw new ConflictError("Two factor authentication is not setup for this user");
        }
        const twoFactorSecret = decryptSecret(encryptedSecret);
        const totp = generateTOTP(input.email, twoFactorSecret);
        const delta = totp.validate({
            token: input.token,
            window: 1,
        });

        if (delta === null) {
            throw new ConflictError("Invalid token");
        }
        await AuthRepository.enableTwoFactorAuth(input.email, logger);
        return { message: "Two factor authentication verified successfully" };
    }

}


export default new AuthService();