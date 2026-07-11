
import { Request, Response, NextFunction } from "express";
import SessionService from "./session.service.js";

export async function logoutFromAllDevices(req: Request, res: Response, next: NextFunction) {
    try {
        const userId = req.user.userId;
        console.log("User ID from request: %s", userId);
        await SessionService.logoutFromAllDevices(userId!, req.log);
        res.clearCookie("accessToken").clearCookie("refreshToken").json({ success: true, message: "Logged out from all devices" });
    } catch (error) {
        next(error);
    }
}



export const getSession = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const sessionId = req.user.sessionId;
        if (!sessionId) {
            return res.status(400).json({ success: false, message: "Session ID is missing" });
        }
        const session = await SessionService.getSession(sessionId, req.log);

        if (!session) {
            return res.status(404).json({ success: false, message: "Session not found" });
        }
        res.json({ success: true, session, user: req.user });
    } catch (error) {
        next(error);
    }
}

export const refreshToken = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const refreshToken = req.cookies.refreshToken;
        if (!refreshToken) {
            return res.status(400).json({ success: false, message: "Refresh token is missing" });
        }
        const tokens = await SessionService.refreshToken(refreshToken, req.log);
        if (tokens) {
            res
                .status(200)
                .cookie("accessToken", tokens.accessToken, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === "production",
                    sameSite: "strict",
                    maxAge: 15 * 60 * 1000,
                })
                .json({ success: true, accessToken: tokens.accessToken });
        } else {
            res.status(401).json({ success: false, message: "Invalid refresh token" });
        }
    } catch (error) {
        next(error);
    }
}

export const logoutFromDevice = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const sessionId = req.user.sessionId;
        if (!sessionId) {
            return res.status(400).json({ success: false, message: "Session ID is missing" });
        }
        await SessionService.logoutFromDevice(sessionId, req.log);
        res.clearCookie("accessToken").clearCookie("refreshToken").json({ success: true, message: "Logged out from current device" });
    } catch (error) {
        next(error);
    }
}
