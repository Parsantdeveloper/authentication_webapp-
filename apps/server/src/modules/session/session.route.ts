
import express from "express";
import {  getSession, logoutFromAllDevices, logoutFromDevice, refreshToken} from "./session.controller.js";
import { authMiddleware } from "../../middlewares/authenticate.js";

const router = express.Router();


/**
 * @swagger
 * /api/session/logout-all:
 *   post:
 *     summary: Logout from all devices
 *     description: Invalidates all sessions for the authenticated user across all devices
 *     tags:
 *       - Authentication
 *     security:
 *       - cookieAuth: []
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Successfully logged out from all devices
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: "Logged out from all devices"
 *         headers:
 *           Set-Cookie:
 *             schema:
 *               type: string
 *               example: "accessToken=; Path=/; HttpOnly; Secure; SameSite=Strict; refreshToken=; Path=/; HttpOnly; Secure; SameSite=Strict"
 *       401:
 *         description: Unauthorized - No valid token provided
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: "Unauthorized"
 */
router.post("/logout-all", authMiddleware, logoutFromAllDevices);


/**
 * @swagger
 * /api/session/session:
 *   get:
 *     summary: Get current session information
 *     description: Retrieves the current user's session information and details
 *     tags:
 *       - Authentication
 *     security:
 *       - cookieAuth: []
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Session retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 session:
 *                   type: object
 *                   description: Session details including device, location, created_at, etc.
 *                 user:
 *                   type: object
 *                   description: User information extracted from token
 *       400:
 *         description: Session ID is missing
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: "Session ID is missing"
 *       401:
 *         description: Unauthorized - No valid token provided
 *       404:
 *         description: Session not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: "Session not found"
 */
router.get("/session", authMiddleware, getSession);

/**
 * @swagger
 * /api/session/refresh-token:
 *   get:
 *     summary: Refresh access token
 *     description: Uses the refresh token from cookies to issue a new access token without requiring re-authentication
 *     tags:
 *       - Authentication
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Access token refreshed successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 accessToken:
 *                   type: string
 *                   description: New access token (15 minutes validity)
 *         headers:
 *           Set-Cookie:
 *             schema:
 *               type: string
 *               example: "accessToken=...; Path=/; HttpOnly; Secure; SameSite=Strict"
 *       400:
 *         description: Refresh token is missing or invalid
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *       401:
 *         description: Refresh token is invalid or expired
 */
router.get("/refresh-token", refreshToken);

/**
 * @swagger
 * components:
 *   securitySchemes:
 *     cookieAuth:
 *       type: apiKey
 *       in: cookie
 *       name: accessToken
 *       description: Access token stored in httpOnly cookie
 *     bearerAuth:
 *       type: http
 *       scheme: bearer
 *       bearerFormat: JWT
 *   schemas:
 *     User:
 *       type: object
 *       properties:
 *         userId:
 *           type: string
 *           format: uuid
 *         email:
 *           type: string
 *           format: email
 *         name:
 *           type: string
 *         created_at:
 *           type: string
 *           format: date-time
 *     Session:
 *       type: object
 *       properties:
 *         sessionId:
 *           type: string
 *           format: uuid
 *         userId:
 *           type: string
 *           format: uuid
 *         device:
 *           type: string
 *         location:
 *           type: string
 *         ipAddress:
 *           type: string
 *         created_at:
 *           type: string
 *           format: date-time
 *         last_activity:
 *           type: string
 *           format: date-time
 */


router.post("/logout", authMiddleware, logoutFromDevice);
/**
 * @swagger
 * /api/session/logout:
 *   post:
 *     summary: Logout from current device
 *     description: Invalidates the current session, logging the user out from the current device
 *     tags:
 *       - Authentication
 *     security:
 *       - cookieAuth: []
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Successfully logged out from current device
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: "Logged out from current device"
 *         headers:
 *           Set-Cookie:
 *             schema:
 *               type: string
 *               example: "accessToken=; Path=/; HttpOnly; Secure; SameSite=Strict; refreshToken=; Path=/; HttpOnly; Secure; SameSite=Strict"
 *       400:
 *         description: Session ID is missing
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: "Session ID is missing"
 *       401:
 *         description: Unauthorized - No valid token provided
 *       404:
 *         description: Session not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: "Session not found" 
 */


export default router;