
import express from "express";
import { emailLogin, emailSignup } from "./auth.controller.js";

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



export default router;