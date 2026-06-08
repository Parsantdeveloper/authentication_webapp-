import { Request, Response, NextFunction } from "express";
import { ZodError } from "zod";
import { AppError } from "@repo/errors";
import { logger } from "../config/logger.js";
import { EmailAlreadyExistsError } from "@repo/errors";
export const errorHandler = (
  err: any,
  req: Request,
  res: Response,
  _next: NextFunction
) => {

  const log = req.log??logger;
  // Zod validation errors
  if (err instanceof ZodError) {
    return res.status(400).json({
      success: false,
      message: "Validation error",
      errors: err.flatten(),
    });
  }

  // Known operational errors
  if (err instanceof AppError) {
    return res.status(err.statusCode).json({
      success: false,
      message: err.message,
    });
  }
     if (err instanceof EmailAlreadyExistsError) {
      return res.status(409).send({ message: err.message });
    }

  // Unknown / programmer errors
  log.error("UNHANDLED ERROR 💥", err);

  return res.status(500).json({
    success: false,
    message: "Internal Server Error",
  });
};
