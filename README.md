# ITC Infotech Secure Login Lab

A runnable login and account-recovery demo for the ITC Infotech campus-drive problem statement. Cloud Firestore stores users, reset records, and server-side sessions. Redis is used for shared login throttling on Render. The four-slide interview presentation remains included.

## Run locally

Requirements: Node.js 22+. To use shared local rate limits, also install Docker Desktop.

1. Install dependencies:

   ```powershell
   npm.cmd install
   ```

2. Create a Firestore database in the Firebase Console using Firestore Native mode and enable the Cloud Firestore API.
3. Revoke any service-account key that has been shared or committed. Create a replacement key with only the Firestore permissions this app needs. Save the new file as `firebase-service-account.json` in this directory. It is excluded from Git.
4. Copy `.env.example` to `.env`. The example already points `GOOGLE_APPLICATION_CREDENTIALS` to that credential file. Replace the session and TOTP secrets with random values of at least 32 characters.
5. Optionally start local Redis/Valkey for shared throttles:

   ```powershell
   docker compose up -d
   ```

   Without Redis, local rate limits use Express's in-memory store and reset when the app restarts.
6. Start the app:

   ```powershell
   npm.cmd start
   ```

Open `http://localhost:3000`, create an account, then sign in and enable authenticator MFA. Password-reset emails require a verified sender, `RESEND_API_KEY`, and `MAIL_FROM`.

## Deploy on Render

The root `render.yaml` is a Render Blueprint for the web app and a private Key Value service. User records and sessions persist in Firestore, so no Render PostgreSQL database is provisioned.

1. In Firebase, create Firestore in Native mode and generate a **new** service-account key after revoking any key shared in chat.
2. Push the project to a GitHub repository connected to Render.
3. In Render, choose **New → Blueprint**, select the repository, and apply `render.yaml`.
4. When prompted for `FIREBASE_SERVICE_ACCOUNT_JSON_B64`, provide the new service-account JSON encoded as one Base64 line. In PowerShell, from the directory containing the new key:

   ```powershell
   [Convert]::ToBase64String([IO.File]::ReadAllBytes('.\\firebase-service-account.json'))
   ```

   Paste the output into Render's secret prompt. Never commit the key or paste it into source code.
5. Render generates the session and TOTP encryption secrets. Add `RESEND_API_KEY` and `MAIL_FROM` in the service settings if you want email recovery. Verify the sending domain with Resend first.
6. Wait for `/healthz` to pass, then open the service's `onrender.com` URL.

The Blueprint uses Render's free web and Key Value plans for a demo. The web service can sleep when idle and free Key Value data is not persistent. Firestore usage and quotas are governed by the Firebase project and billing settings. See [Render's free-plan limits](https://render.com/docs/free).

## Security controls

- Passwords use Argon2id with a unique salt; plaintext passwords are not stored or logged.
- Firestore document IDs for users are stable SHA-256 identifiers derived from normalized email addresses; this does not make the email value private.
- Login lookups use a deterministic hashed document ID rather than constructing database queries from user input.
- Sessions are stored server-side in Firestore and use `Secure`, `HttpOnly`, and `SameSite=Lax` cookies in production. Login rotates the session ID.
- State-changing requests require a session-bound CSRF token.
- Redis applies shared IP throttles and failed-attempt limits by account/IP in production.
- TOTP secrets are encrypted at rest with AES-256-GCM using a separate secret.
- Reset tokens are random, stored only as SHA-256 hashes, expire after 15 minutes, and are single-use. A successful reset increments the password/session versions and deletes stored sessions.
- Helmet supplies browser security headers and a same-origin Content Security Policy.
- Firebase Admin is a privileged server SDK. Do not expose its service-account key to the browser. Restrict the service account to least privilege and keep its JSON out of Git.

This is an interview/demo project. Have it independently reviewed and penetration tested before using it for customer accounts.

## Project files

- `app.js` — Express app, Firebase Admin/Firestore setup, authentication, sessions, and recovery
- `public/` — responsive login, registration, recovery, MFA, and authenticated dashboard UI
- `render.yaml` — Render Blueprint
- `docker-compose.yml` — optional local Valkey service
- `.env.example` — local environment template
- `generate_presentation.js` — PowerPoint generator
- `ITC_Infotech_Securing_Login_Page.pptx` — four-slide interview presentation
- `validate_presentation.js` — presentation package validator

The Firebase JSON file in the workspace is ignored by Git. If that key has been shared, revoke it and use a replacement.
