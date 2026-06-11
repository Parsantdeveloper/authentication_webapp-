
import { z } from "zod";

const baseAuthSchema = z.object({

  ipAddress: z
    .string()
    .optional()
    .refine(
      (val) =>
        !val ||
        /^(?:\d{1,3}\.){3}\d{1,3}$/.test(val) ||
        /^([a-fA-F0-9:]+)$/.test(val),
      {
        message: "Invalid IP address",
      }
    ),

  device: z
    .string()
    .max(100, "Device name too long")
    .optional(),

  location: z
    .string()
    .max(150, "Location too long")
    .optional(),

  user_agent: z
    .string()
    .max(300, "User agent too long")
    .optional(),
});

export const sessionCreateSchema = baseAuthSchema.extend({
  userId: z.string().uuid("Invalid user ID format"),
  token: z.string(),
  ipAddress:z.string().optional(),
  device: z.string().optional(),
  location: z.string().optional(),
  user_agent: z.string().optional(),

})
export type SessionCreateInput = z.infer<typeof sessionCreateSchema>;
export const emailSignupSchema = baseAuthSchema.extend({
  email: z
    .string()
    .email("Invalid email format"),

  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .max(128, "Password must not exceed 128 characters"),

  name: z
    .string()
    .min(2, "Name must be at least 2 characters")
    .max(150, "Name must not exceed 150 characters"),
  
  provider: z.literal("email").default("email").optional(),
});

export type EmailSignupInput = z.infer<typeof emailSignupSchema>;


export const phoneSignupSchema = baseAuthSchema.extend({
  phoneNumber: z.string().min(10).max(10).regex(/^d{10}$/, "Invalid phone number"),
  name: z.string().min(2).max(150)

})

export const emailLoginSchema = baseAuthSchema.extend({
  email: z.string().email(),
  password: z.string().min(8).max(128)
})
export type EmailLoginInput = z.infer<typeof emailLoginSchema>;
export const phoneLoginSchema = baseAuthSchema.extend({
  phoneNumber: z.string().min(10).max(10).regex(/^d{10}$/, "Invalid phone number"),
  password: z.string().min(8).max(128)
})
export type PhoneLoginInput = z.infer<typeof phoneLoginSchema>;

