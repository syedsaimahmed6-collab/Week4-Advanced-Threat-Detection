# Week 4 – Advanced Threat Detection & Web Security Enhancements

**Intern:** Syed Saim Ahmed
**ID:** DHC-1014
**Date:** June 2026

## What was done in Week 4
- Set up intrusion detection using Fail2Ban
- Added in-app login attempt tracking with auto lockout
- Implemented rate limiting using express-rate-limit
- Fixed CORS to restrict to trusted origins only
- Added API key authentication on all CRUD routes
- Implemented full Content Security Policy (CSP)
- Enabled HSTS for HTTPS enforcement

## New packages installed
npm install express-rate-limit cors dotenv

## How to Run
1. Clone the repo
   git clone https://github.com/YourUsername/Week4-Advanced-Threat-Detection
2. Install dependencies
   npm install
3. Create a .env file with your secrets (see .env.example)
4. Start the server
   node index.js
5. Open https://localhost:8443

## Security Features in this version
- Rate limiting: 100 requests per 15 min (general)
- Rate limiting: 10 login attempts per 10 min (login route)
- CORS: restricted to localhost:5000 and localhost:3000 only
- API key required on all CRUD routes (x-api-key header)
- Full CSP via Helmet including frameAncestors and formAction
- HSTS: 1 year, includeSubDomains, preload

## Files
- index.js — main server with all Week 4 changes
- middleware/authenticateToken.js — JWT middleware
- middleware/checkApiKey.js — API key middleware
- .env.example — template for environment variables
- security.log — sample log output
