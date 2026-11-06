# Harrington Verve — website

Static site + one serverless function (`api/enquiry.js`) for the introduction form. No database, no build step, no runtime dependencies.

## Deploy on Vercel
1. Create a Vercel account owned by Harrington Verve and import this folder (or a Git repo containing it). Framework preset: "Other". No build command.
2. In Settings > Environment Variables add the values listed in `.env.example`.
3. In Resend, verify the domain harringtonverve.com (SPF/DKIM) so `MAIL_FROM` can send.
4. Open the preview URL, send a test enquiry, and check headers at securityheaders.com.
5. In Firewall, add a rate-limit rule for `/api/enquiry`.
6. Point the domain to Vercel.

## Tests
`npm test` (Node 20+). Runs the security tests for the form endpoint and the header configuration.
