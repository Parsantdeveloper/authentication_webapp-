
import { Request, Response, NextFunction } from "express";
import AuthService from "./auth.service.js";
import {  emailSignupSchema } from "./auth.schema.js";
import { logger } from "../../config/logger.js";
export  async function emailSignup(req: Request, res: Response, next: NextFunction) {
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
            .json({ success: true, accessToken: tokens.accessToken, refreshToken: tokens.refreshToken });

    } catch (error) {
     
        next(error);
    }
}
