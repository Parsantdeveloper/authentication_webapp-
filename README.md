1. Email + Password      ✅

2. Refresh Tokens        ✅

3. Email Verification

4. Password Reset

5. TOTP Authenticator

6. Recovery Codes

7. Trusted Devices

8. Magic Links

9. Google OAuth

10. GitHub OAuth

11. Step-up Authentication

12. Session Dashboard

13. Passkeys (WebAuthn)

14. Device Fingerprinting

15. Risk-based Authentication


APIs I would build next

Order matters.

Phase 1
POST /auth/signup
POST /auth/login

POST /auth/refresh
POST /auth/logout

GET  /auth/me

You already have most of this.

Phase 2

POST /auth/email-verification/request
POST /auth/email-verification/verify

Phase 3
POST /auth/password-reset/request
POST /auth/password-reset/verify


Phase 4
POST /auth/magic-link/request
GET  /auth/magic-link/verify
Phase 5
POST /2fa/setup
POST /2fa/verify-setup

POST /2fa/login
POST /2fa/disable
Phase 6
GET /oauth/google
GET /oauth/google/callback

GET /oauth/github
GET /oauth/github/callback

Phase 7
GET /sessions

DELETE /sessions/:id

DELETE /sessions