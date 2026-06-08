import { z } from "zod";
import dotenv from "dotenv"
dotenv.config()
const envSchema = z.object({
NODE_ENV: z.enum(["development", "production", "test"]),
PORT: z.string(),
DATABASE_URL: z.string().url(),
LOG_LEVEL: z.enum(["debug", "info", "warn", "error"]).default("info"),
JWT_SECRET: z.string(),
});


const parsed = envSchema.safeParse(process.env);


if (!parsed.success) {
console.error(parsed.error.format());
process.exit(1);
}


export const env = parsed.data;