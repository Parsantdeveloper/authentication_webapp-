import { Request, Response, NextFunction } from "express";
import { verifyAccessToken } from "@repo/auth-utils";

export const authMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    let token: string | undefined;

    const authHeader = req.headers.authorization;

    if (authHeader?.startsWith("Bearer ")) {
      token = authHeader.split(" ")[1];
    }

    if (!token && req.cookies?.accessToken) {
      token = req.cookies.accessToken;
    }

    if (!token) {
      return res.status(401).json({
        message: "Unauthorized",
      });
    }

    req.user = verifyAccessToken(token);
    next();
  } catch {
    return res.status(401).json({
      message: "Invalid or expired token",
    });
  }
};