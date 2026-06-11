
import express from "express";
import { emailLogin, emailSignup,  getSession,  logoutFromAllDevices, refreshToken } from "./auth.controller.js";
import { authMiddleware } from "../../middlewares/authenticate.js";

const router = express.Router();

router.post("/email-signup", emailSignup);

router.post("/logout-all", authMiddleware, logoutFromAllDevices);

router.post("/email-login", emailLogin);

router.get("/session" , authMiddleware, getSession);

router.get("/refresh-token", refreshToken);

export default router;      