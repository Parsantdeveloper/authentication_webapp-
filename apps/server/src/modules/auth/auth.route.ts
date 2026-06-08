
import express from "express";
import { emailSignup } from "./auth.controller.js";

const router = express.Router();

router.post("/email-signup", emailSignup);

export default router;