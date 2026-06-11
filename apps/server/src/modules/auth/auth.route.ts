
import express from "express";
import { emailLogin, emailSignup,  getSession,  logoutFromAllDevices, refreshToken } from "./auth.controller.js";
import { authMiddleware } from "../../middlewares/authenticate.js";

const router = express.Router();

/**
 * @swagger
 * /api/auth/email-signup:
 *   post:
 *     summary: Register a new user with email
 *     description: Creates a new user account with email and password. Returns access and refresh tokens.
 *     tags:
 *       - Authentication
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *               - name
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 description: User's email address
 *                 example: user@example.com
 *               password:
 *                 type: string
 *                 format: password
 *                 minLength: 8
 *                 maxLength: 128
 *                 description: User's password (min 8 characters)
 *                 example: SecurePassword123!
 *               name:
 *                 type: string
 *                 minLength: 2
 *                 maxLength: 150
 *                 description: User's full name
 *                 example: John Doe
 *               device:
 *                 type: string
 *                 maxLength: 100
 *                 description: Device name (optional)
 *                 example: iPhone 12
 *               location:
 *                 type: string
 *                 maxLength: 150
 *                 description: User location (optional)
 *                 example: New York, USA
 *               ipAddress:
 *                 type: string
 *                 description: IP address (optional)
 *                 example: 192.168.1.1
 *               user_agent:
 *                 type: string
 *                 maxLength: 300
 *                 description: User agent string (optional)
 *     responses:
 *       201:
 *         description: Account created successfully
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
 *                   description: Session object with user information
 *                 accessToken:
 *                   type: string
 *                   description: Short-lived access token (15 minutes)
 *                 refreshToken:
 *                   type: string
 *                   description: Long-lived refresh token (30 days)
 *         headers:
 *           Set-Cookie:
 *             schema:
 *               type: string
 *               example: "accessToken=...; Path=/; HttpOnly; Secure; SameSite=Strict; refreshToken=...; Path=/; HttpOnly; Secure; SameSite=Strict"
 *       400:
 *         description: Validation error or invalid input
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
 *       409:
 *         description: Email already exists
 */
router.post("/email-signup", emailSignup);

/**
 * @swagger
 * /api/auth/logout-all:
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
 * /api/auth/email-login:
 *   post:
 *     summary: Login with email and password
 *     description: Authenticates a user with email and password. Returns access and refresh tokens.
 *     tags:
 *       - Authentication
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 description: User's email address
 *                 example: user@example.com
 *               password:
 *                 type: string
 *                 format: password
 *                 minLength: 8
 *                 maxLength: 128
 *                 description: User's password
 *                 example: SecurePassword123!
 *               device:
 *                 type: string
 *                 maxLength: 100
 *                 description: Device name (optional)
 *               location:
 *                 type: string
 *                 maxLength: 150
 *                 description: User location (optional)
 *               ipAddress:
 *                 type: string
 *                 description: IP address (optional)
 *               user_agent:
 *                 type: string
 *                 maxLength: 300
 *                 description: User agent string (optional)
 *     responses:
 *       200:
 *         description: Login successful
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
 *                   description: Session object with user information
 *                 accessToken:
 *                   type: string
 *                   description: Short-lived access token (15 minutes)
 *                 refreshToken:
 *                   type: string
 *                   description: Long-lived refresh token (30 days)
 *         headers:
 *           Set-Cookie:
 *             schema:
 *               type: string
 *               example: "accessToken=...; Path=/; HttpOnly; Secure; SameSite=Strict; refreshToken=...; Path=/; HttpOnly; Secure; SameSite=Strict"
 *       400:
 *         description: Validation error or invalid credentials
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
 *         description: Invalid email or password
 */
router.post("/email-login", emailLogin);

/**
 * @swagger
 * /api/auth/session:
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
 * /api/auth/refresh-token:
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

export default router;