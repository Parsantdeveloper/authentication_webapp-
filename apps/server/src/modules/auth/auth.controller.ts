
import { Request, Response, NextFunction } from "express";
import AuthService from "./auth.service.js";
import { emailSignupSchema, emailLoginSchema} from "./auth.schema.js";
import { logger } from "../../config/logger.js";
export async function emailSignup(req: Request, res: Response, next: NextFunction) {
    try {
        const input = emailSignupSchema.parse({
            ...req.body,
            // ipAddress: req.ip,
            // user_agent: req.headers["user-agent"],
            // device: req.body.device || "unknown",
            // location: req.body.location || "unknown"
        });
        const cookieOptions = {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict" as const,
        };
        const tokens = await AuthService.emailSignup(input, req.log);
        logger.info("Email signup successful for email: %s", tokens.refreshToken);
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

    } catch (error) {

        next(error);
    }
}


export async function emailLogin(req: Request, res: Response, next: NextFunction) {
    try {
        let input = emailLoginSchema.parse(req.body);
        const tokens = await AuthService.emailLogin(input, req.log);
         

        if (tokens.requiresTwoFactor===false) {
            res
                .status(200)
                .cookie("accessToken", tokens.accessToken, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === "production",
                    sameSite: "strict",
                    maxAge: 15 * 60 * 1000,
                })
                .cookie("refreshToken", tokens.refreshToken, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === "production",
                    sameSite: "strict",
                    maxAge: 30 * 24 * 60 * 60 * 1000,
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

