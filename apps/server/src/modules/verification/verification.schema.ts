
import { z } from "zod";
import { baseAuthSchema } from "../auth/auth.schema.js";




export const verificationSchema = z.object({
   code: z.string().length(6, "Verification code must be 6 characters"),
}
)

export const changePasswordInput=z.object({
    old_password:z.string(),
    new_password:z.string().min(6,"password must be at least 6 characters")
})

export const magicLinkSchema = baseAuthSchema.extend({
  email: z.string().email("Invalid email format"),
})


export const totpVerifySchema = z.object({
  token: z.string().length(6, "TOTP token must be 6 characters"),
})
