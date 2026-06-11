
import { Request, Response, NextFunction } from "express";
import AuthService from "./auth.service.js";
import {  emailSignupSchema , emailLoginSchema } from "./auth.schema.js";
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
            .json({ success: true, session: tokens.session, accessToken: tokens.accessToken, refreshToken: tokens.refreshToken });

    } catch (error) {
     
        next(error);
    }
}

export async function logoutFromAllDevices(req: Request, res: Response, next: NextFunction) {
    try{
        const userId = req.user.userId;
         console.log("User ID from request: %s", userId);
         await AuthService.logoutFromAllDevices(userId!, req.log);
         res.clearCookie("accessToken").clearCookie("refreshToken").json({ success: true, message: "Logged out from all devices" });
    }catch(error){
        next(error);
    }
}

export async function emailLogin(req: Request, res: Response, next: NextFunction) {
    try {
      let input = emailLoginSchema.parse(req.body);
      const tokens = await AuthService.emailLogin(input, req.log);
      if(tokens){
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
      }
      
    }catch(error){
        next(error);
    }
}


export const getSession = async(req: Request, res: Response, next: NextFunction) => {
    try{
        const sessionId = req.user.sessionId;
        if(!sessionId){
            return res.status(400).json({ success: false, message: "Session ID is missing" });
        }
        const session = await AuthService.getSession(sessionId, req.log);
        
        if(!session){
            return res.status(404).json({ success: false, message: "Session not found" });
        }
        res.json({ success: true, session ,user:req.user});
    }catch(error){
        next(error);
    }
}

export const refreshToken = async(req: Request, res: Response, next: NextFunction) => {
    try{
        const refreshToken = req.cookies.refreshToken;
        if(!refreshToken){
            return res.status(400).json({ success: false, message: "Refresh token is missing" });
        }
        const tokens = await AuthService.refreshToken(refreshToken, req.log);
        if(tokens){
            res
            .status(200)
            .cookie("accessToken", tokens.accessToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                sameSite: "strict",
                maxAge: 15 * 60 * 1000,
            })
            .json({ success: true, accessToken: tokens.accessToken });
        }else{
            res.status(401).json({ success: false, message: "Invalid refresh token" });
        }
    }catch(error){
        next(error);
    }
}