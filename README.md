# ECO Budget — Render + PostgreSQL

## Deploy to Render
1. Push this project folder to a GitHub repository. Do not commit `.env`, API keys, passwords, or database URLs.
2. Create a Render PostgreSQL database. The free database shown in Render may expire after its stated trial period; do not rely on it for long-term production data.
3. Create a Render **Web Service** from the repository with build command `npm install` and start command `npm start`.
4. In the Web Service's Environment settings, set:
   - `DATABASE_URL`: copy the PostgreSQL **Internal Database URL** from the Render database page when the web service and database are in the same Render region. If they are in different regions, use the provider's supported connection URL.
   - `APP_URL`: the exact HTTPS URL of your deployed Render Web Service, e.g. `https://your-service.onrender.com` (no trailing slash).
   - `JWT_SECRET`: a random secret of at least 32 characters.
   - `GEMINI_API_KEY`, `GEMINI_MODEL`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`.
   - `NODE_ENV=production`
5. Deploy. On startup, the server creates the `users` table if it does not exist.
6. Test registration with an email address you can access, open the verification email on your phone, then log in and log out/in again.

## Notes
- User accounts and email-verification state are stored in PostgreSQL, not a local JSON file.
- Verification tokens are stored as SHA-256 hashes and expire after 30 minutes.
- Verification is one-time. Logging out does not reset the verified status or send another verification email.
- The current schema does not automatically import accounts from a previous `data/users.json`. Existing local users need to register again after deployment unless you explicitly migrate them.
- Keep secrets out of source control and never share database connection URLs publicly.
