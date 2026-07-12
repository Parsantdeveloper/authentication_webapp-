
import AuthRepository from "../auth/auth.repo.js";
import SessionService from "../session/session.service.js";
import VerificationRepository from "./verification.repo.js";
import { hashSecret, hashToken, compareSecret, generateOTP } from "@repo/auth-utils"
import { generateToken, generatePasswordResetToken, verifyPasswordResetToken ,generateLoginToken,verifyLoginToken,decryptSecret, encryptSecret, generateSecret, generateTOTP  } from "@repo/auth-utils"
import emailQueue from "../../libs/email.subscriber.js"
import type { Logger } from "../../config/logger.js";
import { ConflictError, AppError } from "@repo/errors";
import { VerifyCode, changePasswordTypes } from "./verification.type.js";
import QRCode from "qrcode";






interface SessionInput {
    device?: string;
    location?: string;
    user_agent?: string;
    ipAddress?: string;
}


class AuthService {


  

    async sendEmailVerification(email: string, logger: Logger) {
        const code = generateOTP(6);
        const hashedCode = await hashSecret(code);
        const verification_exist = await VerificationRepository.getVerificationByIdentifier(email, "EMAIL_VERIFICATION", logger);
        if (verification_exist) {
            logger.info("Existing verification code found for email: %s", email);
            throw new ConflictError("Verification code already sent. Please check your email. or wait for the previous code to expire.");
        }
        const verification = await VerificationRepository.createVerification({
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

        const verification = await VerificationRepository.getVerificationByIdentifier(input.identifier, input.type, logger);
        const isValid = await compareSecret(input.code, verification?.tokenHash ?? "");
        if (!verification || !isValid) {
            logger.warn("Invalid verification attempt for identifier: %s", input.identifier);
            throw new ConflictError("Invalid verification code");
        }
        const user = await VerificationRepository.verifyEmail(input.identifier, logger);
        await VerificationRepository.markVerificationAsUsed(verification.id, logger);
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
            await VerificationRepository.changePassword(account.id, newHashedPassword);
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

        const verification_exist = await VerificationRepository.getVerificationByIdentifier(email, "PASSWORD_RESET", logger);
        if (verification_exist) {
            logger.info("Existing password reset code found for email: %s", email);
            throw new ConflictError("Password reset code already sent. Please check your email. or wait for the previous code to expire.");
        }
        const verification = await VerificationRepository.createVerification({
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

        const verification = await VerificationRepository.getVerificationByIdentifier(input.identifier, "PASSWORD_RESET", logger);
        const isValid = await compareSecret(input.code, verification?.tokenHash ?? "");
        if (!verification || !isValid) {
            logger.warn("Invalid verification attempt for identifier: %s", input.identifier);
            throw new ConflictError("Invalid verification code");
        }

        const reset_token = generatePasswordResetToken({ userId: input.userId, purpose: "PASSWORD_RESET" });
        await VerificationRepository.markVerificationAsUsed(verification.id, logger);
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
            await VerificationRepository.changePassword(account.id, newHashedPassword);
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
        const verification_exist = await VerificationRepository.getVerificationByIdentifier(email, "MAGIC_LINK", logger);
        if (verification_exist) {
            logger.info("Existing magic link found for email: %s", email);
            throw new ConflictError("Magic link already sent. Please check your email. or wait for the previous link to expire.");
        }
        const verification = await VerificationRepository.createVerification({
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
        const verification = await VerificationRepository.getVerificationByHashedToken(tokenHash, "MAGIC_LINK", logger);
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

      await VerificationRepository.markVerificationAsUsed(verification.id, logger);


        if(!user.twoFactorEnabled){
         let { session, accessToken, refreshToken } = await SessionService.createSession(user, sessionInput, logger);
        return ({ session, accessToken, refreshToken });
        }

      const loginToken = generateLoginToken({ userId: user.id, type: "2fa_login" });
        return { requiresTwoFactor: true, loginToken , message: "Two-factor authentication is enabled. Please verify the 2FA token."};
       
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
        const twoFactorSecret = await VerificationRepository.addTwoFactorSecret(email, encryptedSecret, logger);
        if (!twoFactorSecret) {
            throw new ConflictError("Failed to setup two factor authentication");
        }
        const url = totp.toString();
        const qrCode = await QRCode.toDataURL(url);
        return { qrCode };
    }



    async verify2fa(input: { email: string; token: string }, logger: Logger) {
        const encryptedSecret = await VerificationRepository.getTwoFactorSecret(input.email, logger);
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
        await VerificationRepository.enableTwoFactorAuth(input.email, logger);
        return { message: "Two factor authentication verified successfully" };
    }

    async verify2faLogin(input:{loginToken:string,token:string},sessionInput:SessionInput,logger:Logger){

        console.log("req comming in service")
         const payload = verifyLoginToken(input.loginToken);
         if(!payload || payload.type!=="2fa_login"){
            throw new ConflictError("Invalid or expired login token");
         }
         console.log("payload",payload)
         const user = await AuthRepository.getUserById(payload.userId);
         console.log("user",user)
         if (!user) {
            throw new ConflictError("User not found");
         }
         console.log("user request in comming")
        
         const twoFactorSecret =decryptSecret(user.twoFactorSecret??"");
            const totp = generateTOTP(user.email, twoFactorSecret);
             const delta = totp.validate({
            token: input.token,
            window: 1,
        });
        
        if (delta === null) {
            throw new ConflictError("Invalid token");
        }
       let { session, accessToken, refreshToken } = await SessionService.createSession(user, sessionInput, logger);
            return ({requiresTwoFactor: false, session, accessToken, refreshToken });
       
    }

    async disable2fa(input:{email:string,token:string},logger:Logger){
        const user = await AuthRepository.checkUserExistsByEmail(input.email);
        if (!user) {
            throw new ConflictError("User doesnot exists");
        }
        if(user.twoFactorEnabled===false){
            throw new ConflictError("Two-factor authentication is not enabled.");
        }
        const twoFactorSecret =decryptSecret(user.twoFactorSecret??"");
        const totp = generateTOTP(input.email, twoFactorSecret);
        const delta = totp.validate({
            token: input.token,
            window: 1,
        });
        
        if (delta === null) {
            throw new ConflictError("Invalid token");
        }
        await VerificationRepository.disableTwoFactorAuth(input.email, logger);
        return { message: "Two factor authentication disabled successfully" };
    }



    
}


export default new AuthService();