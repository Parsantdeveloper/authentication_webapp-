
import { z } from "zod";
import { baseAuthSchema } from "../auth/auth.schema.js";

export const sessionCreateSchema = baseAuthSchema.extend({
  userId: z.string().uuid("Invalid user ID format"),
  token: z.string(),
  ipAddress:z.string().optional(),
  device: z.string().optional(),
  location: z.string().optional(),
  user_agent: z.string().optional(),

})
export type SessionCreateInput = z.infer<typeof sessionCreateSchema>;


