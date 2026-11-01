# ITC Infotech Secure Login Lab

A runnable web application that turns the campus-drive login problem into an interactive demo. It includes registration and login, Argon2id password hashing, PostgreSQL-backed server sessions, CSRF tokens, Redis-backed throttling, optional authenticator-app TOTP MFA, and one-use password reset links. The four-slide interview presentation remains available in the project folder.

## Run locally

Requirements: Node.js 18+ and Docker Desktop (or local PostgreSQL 16 and Valkey/Redis).

1. Install the Node packages:

   ```powershell
   npm.cmd install
   ```

2. Start PostgreSQL and Valkey in separate containers:

   ```powershell
   docker compose up -d
   ```

3. Create `.env` from `.env.example`. Keep the example database URL and Redis URL for Docker. Replace the session secret and TOTP encryption key with random values of at least 32 characters.

   ```powershell
   Copy-Item .env.example .env
   ```

4. Run the app; it reads `.env` automatically:

   ```powershell
   npm.cmd start
   ```

Open `http://localhost:3000`. Register an account, sign in, and enable MFA from the authenticated dashboard. Password reset delivery is enabled after you add a verified sender, `MAIL_FROM`, and a Resend API key.

## Deploy on Render

The root `render.yaml` is a Render Blueprint. It describes the Node web service, a PostgreSQL database, and a private Key Value service used by shared rate limits. The Blueprint generates session and TOTP encryption secrets. During initial Blueprint setup, supply `RESEND_API_KEY` and `MAIL_FROM` if you want password reset emails; verify the sending domain with Resend first.

1. Push this project to a GitHub, GitLab, or Bitbucket repository connected to Render.
2. In Render, choose **New → Blueprint**, select the repository, and apply `render.yaml`.
3. Review the plan choices before applying. The included `free` plans are for a short demo: Render's free web services sleep when idle, free PostgreSQL expires 30 days after creation, and free Key Value data is not persistent. Use paid plans for durable accounts/data.
4. Wait for the deploy to pass `/healthz`, then open the web service's `onrender.com` URL.

Render's Blueprint deploys resources in the Oregon region. Change every region together if you need another Render region.

## Security notes

- Passwords are hashed with Argon2id; plaintext passwords are never written to the database or logs.
- Login queries are parameterized. Responses avoid account enumeration during login and recovery.
- Sessions live in PostgreSQL and use `Secure`, `HttpOnly`, and `SameSite=Lax` cookies in production. The session identifier rotates at login.
- State-changing API requests require a session-bound CSRF token.
- Redis applies IP-based login throttles and failed-attempt limits by account. Redis is required in production so limits are shared between instances.
- TOTP secrets are encrypted at rest with AES-256-GCM using a separate environment secret.
- Reset tokens are random, stored only as SHA-256 hashes, expire after 15 minutes, and are single-use. A successful reset revokes existing sessions.
- Helmet supplies browser security headers and a same-origin Content Security Policy.
- This is an interview/demo application. Have the implementation independently reviewed and penetration tested before using it for real customer accounts.

## Other project files

- `app.js` — Express application and database setup
- `public/` — responsive login, registration, recovery, MFA, and authenticated dashboard UI
- `render.yaml` — Render Blueprint
- `docker-compose.yml` — local PostgreSQL and Valkey services
- `.env.example` — local environment variable template
- `generate_presentation.js` — four-slide PowerPoint source
- `ITC_Infotech_Securing_Login_Page.pptx` — interview presentation
- `validate_presentation.js` — presentation package validator

The Firebase service-account JSON that was previously pasted is an empty placeholder and is excluded from Git. It is not used by this application. Revoke the exposed key in Google Cloud IAM.
