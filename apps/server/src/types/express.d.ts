import type { AccessTokenPayload } from "@repo/auth-utils";

export interface AccessTokenPayload {
  id: string;
  sessionId?: string;
  email: string;
  name: string;
  role: string;
}

declare global {
  namespace Express {
    interface Request {
      user?: AccessTokenPayload;
    }
  }
}

export {};