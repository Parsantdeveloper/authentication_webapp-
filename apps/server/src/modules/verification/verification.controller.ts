
import { Request, Response, NextFunction } from "express";
import VerificationService from "./verification.service.js";
import {  changePasswordInput, magicLinkSchema,  totpVerifySchema } from "./verification.schema.js";
import { VerifyCode } from "./verification.type.js";
import { baseAuthSchema } from "../auth/auth.schema.js";



export const sendVerificationEmail = async (req: Request, res: Response, next: NextFunction) => {

    try {
        const email = req.user.email;
        if (!email) {
            return res.status(400).json({ success: false, message: "Email is missing" });
        }

        let verification = await VerificationService.sendEmailVerification(email, req.log);

        if (verification) return res.status(200).json({ success: true, message: "Email sent successfully" });

    } catch (error) {
        next(error);
    }
}

export const verifyEmail = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const code = req.body.code;
        const email = req.user.email;
        if (!code || !email) {
            return res.status(400).json({ success: false, message: "Code or email is missing" });
        }
        const input: VerifyCode = {
            userId: req.user.id,
            code: code,
            identifier: email,
            type: "EMAIL_VERIFICATION"
        }
        let verification = await VerificationService.verifyEmail(input, req.log);
        if (verification) return res.status(200).json({ success: true, message: "Email verified successfully" });

    } catch (error) {
        next(error);
    }
}


export const changePassword = async (req: Request, res: Response, next: NextFunction) => {

    try {
        const user = req.user;
        const input = changePasswordInput.parse(req.body);
        const body = {
            ...input,
            user_id: req.user.id,
            email: user.email
        }
        console.log("Change password request body: %o", body);
        let result = await VerificationService.passwordChange(body);
        if (result) return res.status(200).json({ success: true, message: "Password changed successfully" });

    } catch (error) {
        next(error);
    }
}

export const sendPasswordResetEmail = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const email = req.user.email;
        if (!email) {
            return res.status(400).json({ success: false, message: "Email is missing" });
        }
        const result = await VerificationService.forgetPassword(email, req.log);
        if (result) return res.status(200).json({ success: true, message: "Password reset email sent successfully" });
    } catch (error) {
        next(error);
    }
}

export const verifyPasswordResetToken = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const token = req.body.token;
        const email = req.user.email;
        let input: VerifyCode = {
            userId: req.user.id,
            code: token,
            identifier: email,
            type: "PASSWORD_RESET"
        }
        if (!token) {
            return res.status(400).json({ success: false, message: "Token is missing" });
        }
        const result = await VerificationService.verifyPasswordResetToken(input, req.log);
        if (result) {
            res
                .status(200)
                .cookie("password_reset_token", result, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === "production",
                    sameSite: "strict",
                    maxAge: 15 * 60 * 1000,
                })
                .json({ success: true, password_reset_token: result });
        } else {
            res.status(401).json({ success: false, message: "Invalid OTP code " });
        }

    } catch (error) {
        next(error);
    }
}

export const verifyPasswordResetTokenAndChangePassword = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const token = req.cookies.password_reset_token;
        if (!token) {
            return res.status(400).json({ success: false, message: "Password reset token is missing" });
        }
        const newPassword = req.body.new_password;
        const password = await VerificationService.changePasswordWithResetToken(token, newPassword, req.log);
        if (password) {
            res.clearCookie("password_reset_token");
            res.status(200).json({ success: true, message: "Password changed successfully" });
        } else {
            res.status(401).json({ success: false, message: "Invalid or expired token" });
        }
    } catch (error) {
        next(error);
    }
}

export const magicLinkRequest = async (req: Request, res: Response, next: NextFunction) => {
    try {
        let email = magicLinkSchema.parse(req.body).email;

        const result = await VerificationService.magicLinkRequest(email, req.log);
        if (result) {
            res.status(200).json({ success: true, message: "Magic link email sent successfully" });
        }
    } catch (error) {
        next(error);
    }
}

export const magicLinkLogin = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const input = baseAuthSchema.parse({
            ...req.body,
        });
        const token = req.query.token as string;
        if (!token) {
            return res.status(400).json({ success: false, message: "Token is missing" });
        }
        const cookieOptions = {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict" as const,
        };
        const tokens = await VerificationService.magicLinkLogin(token, input, req.log);
        if (tokens.requiresTwoFactor===false) {
            res
                .status(201)
                .cookie("accessToken", tokens.accessToken, {
                    ...cookieOptions,

                    maxAge: 15 * 60 * 1000,
                })
                .cookie("refreshToken", tokens.refreshToken, {
                    ...cookieOptions,
                    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
                })
                .json({ success: true, session: tokens.session, accessToken: tokens.accessToken, refreshToken: tokens.refreshToken });
        }else{
             res.status(200)
            .json({ success: true, requiresTwoFactor: true, loginToken: tokens.loginToken, message: "Two-factor authentication is enabled. Please verify the 2FA token." });
           } 
        
        
    } catch (error) {
        next(error);
    }
}


export const setupTwoFactorAuth = async (req: Request, res: Response, next: NextFunction) => {

    try {
        const email = req.user.email;

        const result = await VerificationService.setup2fa(email, req.log);
        if (result) {
            res.status(200).json({ success: true, qrCode: result.qrCode });
        } else {
            res.status(500).json({ success: false, message: "Failed to setup two factor authentication" });
        }

    } catch (error) {
        next(error);
    }
}

export const verifyTwoFactorAuth = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const {token} = totpVerifySchema.parse(req.body);
        const input:{email:string,token:string} ={email:req.user.email,token:token}
        const verify = await VerificationService.verify2fa(input, req.log);
        if (verify) {
            res.status(200).json({ success: true, message: "Two factor authentication verified successfully" });
        } else {
            res.status(401).json({ success: false, message: "Invalid two factor authentication token" });
        }

    } catch (error) {
        next(error);
    }
}

export const verifyTwoFactorAuthLogin = async (req: Request, res: Response, next: NextFunction) => {

    try{

        const {token} = totpVerifySchema.parse(req.body);
        
        const loginToken =req.body.loginToken;

        const sessionInput = baseAuthSchema.parse({
            ...req.body,
        });
        const tokens = await VerificationService.verify2faLogin({loginToken, token}, sessionInput, req.log);
         const cookieOptions = {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict" as const,
        };
        if (tokens) {
           res
            .status(201)
            .cookie("accessToken", tokens.accessToken, {
                ...cookieOptions,

                maxAge: 15 * 60 * 1000,
            })
            .cookie("refreshToken", tokens.refreshToken, {
                ...cookieOptions,
                maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
            })
            .json({ success: true, session: tokens.session, accessToken: tokens.accessToken, refreshToken: tokens.refreshToken });
          
        } else {
            res.status(401).json({ success: false, message: "Invalid two factor authentication token" });
        }
    }catch(error){
        next(error);
    }
}


export const disableTwoFactorAuth = async (req: Request, res: Response, next: NextFunction) => {

    try{
        const input={
            email:req.user.email,
            token:req.body.token
        }
        
        const result = await VerificationService.disable2fa(input, req.log);
        if (result) {
            res.status(200).json({ success: true, message: "Two factor authentication disabled successfully" });
        } else {
            res.status(401).json({ success: false, message: "Invalid two factor authentication token" });
        }
         
    }catch(error){
        next(error);
    }
}