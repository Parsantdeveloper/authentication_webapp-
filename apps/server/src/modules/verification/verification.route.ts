
import express from "express";
import {  changePassword, sendVerificationEmail, verifyEmail, sendPasswordResetEmail, verifyPasswordResetToken, verifyPasswordResetTokenAndChangePassword, magicLinkRequest, magicLinkLogin, setupTwoFactorAuth, verifyTwoFactorAuth, verifyTwoFactorAuthLogin, disableTwoFactorAuth } from "./verification.controller.js";
import { authMiddleware } from "../../middlewares/authenticate.js";

const router = express.Router();


// this route is for sending the verification code to the user's email
router.get("/send-email-verification", authMiddleware, sendVerificationEmail);

// this route is for verifying the email with the code sent to the user's email
router.post("/verify-email", authMiddleware, verifyEmail);


router.post("/change-password", authMiddleware, changePassword);

router.post("/forgot-password", authMiddleware, sendPasswordResetEmail);

router.post("/verify-password-reset", authMiddleware, verifyPasswordResetToken);

router.post("/reset-password", authMiddleware, verifyPasswordResetTokenAndChangePassword);

router.post("/magic-link/request", magicLinkRequest);

router.get("/magic-link/verify", magicLinkLogin);

router.post("/2fa/setup-totp", authMiddleware, setupTwoFactorAuth);

router.post("/2fa/verify-totp", authMiddleware, verifyTwoFactorAuth);

router.post("/2fa/verify-login-totp", verifyTwoFactorAuthLogin);

router.post("/2fa/disable", authMiddleware, disableTwoFactorAuth);

export default router;