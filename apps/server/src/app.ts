import dotenv from "dotenv"

import express from "express";
import cors from "cors";
import helmet from "helmet";
import { errorHandler } from "./middlewares/error_middleware.js";
import { requestLoggerMiddleware } from "./middlewares/request_logger_middleware.js";
import authRouter from "./modules/auth/auth.route.js";
// import { connectDB } from './config/prisma.js'

// import cron from "node-cron";
export const app = express();

dotenv.config();

app.use(
  cors({
    origin: "http://localhost:3000", // Replace with your frontend's origin
    methods: ["GET", "POST", "PUT", "DELETE"], // Specify allowed HTTP methods
    credentials: true, // Allow credentials (cookies, authorization headers, etc.)
  })
);

app.use(helmet());

app.use(express.json());
app.use(requestLoggerMiddleware); // attaches req.log with requestId to every request

app.use("/api/auth", authRouter);


app.use(errorHandler);
export default app;