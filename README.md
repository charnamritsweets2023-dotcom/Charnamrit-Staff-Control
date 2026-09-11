# CHARNAMRIT STAFF CONTROL

## ONE-CLICK DEPLOYMENT

This project includes `render.yaml` for Render Blueprint deployment. Upload the project to GitHub, open Render → New → Blueprint, connect the repository, review the web service + PostgreSQL database, enter the initial Admin values, and deploy.

See `DEPLOY-ONE-CLICK.md` for the exact steps.

# Secure Staff Control — Production Starter

यह demo/localStorage वाला prototype नहीं है। यह real-business deployment के लिए बनाया गया secure full-stack starter है।

## मुख्य permission rules

### ADMIN
- Staff create/manage
- Attendance देखना और correction करना
- Advance request approve/reject
- Approved advance को ledger में डालना
- Security/Audit history
- Salary/financial records

### MANAGER
- Staff की attendance देखना
- केवल **आज** की attendance mark/change करना
- Advance request Admin को भेजना
- **कल या उससे पुरानी attendance change नहीं कर सकता**
- Advance approve नहीं कर सकता
- Advance ledger नहीं बदल सकता
- Salary नहीं देख सकता
- Staff account/settings नहीं बदल सकता

### STAFF
- अपनी attendance देख सकता है
- अपना advance request भेज सकता है
- अपनी finance summary देख सकता है
- दूसरे staff का data नहीं देख सकता

## Security included

- Passwords plaintext में नहीं रखे जाते; scrypt hashing + random salt
- HTTP-only session cookie
- Secure/SameSite cookie settings
- CSRF token for write operations
- Login rate limiting
- Helmet security headers
- Server-side RBAC (frontend permission पर भरोसा नहीं)
- Database constraints
- Advance approval transaction
- Audit log
- Manager historical-attendance lock enforced on server

## सबसे जरूरी: deployment से पहले

1. `.env.example` को `.env` में copy करें।
2. `ADMIN_PASSWORD` को लंबा, unique password दें।
3. `docker-compose.yml` में DB password बदलें और वही password DATABASE_URL में लगाएं।
4. Production में HTTPS reverse proxy (जैसे Nginx/Cloudflare) लगाएं।
5. PostgreSQL का automated encrypted backup और restore test configure करें।
6. Admin account पर 2FA/MFA और password-reset workflow deployment phase में जोड़ना recommended है।
7. Public internet पर लगाने से पहले security audit / penetration test कराएं।

## Run

Docker installed होने पर:

    cp .env.example .env

फिर `.env` में values भरें और:

    docker compose up --build -d

App:

    http://localhost:3000

पहली बार दिए गए ADMIN_EMAIL / ADMIN_PASSWORD से Admin login होगा।

## Important

यह package production architecture और strong server-side controls देता है, लेकिन कोई भी software "100% secure" नहीं होता। Live business use के लिए HTTPS, firewall, backups, monitoring, MFA, dependency updates और security testing जरूरी हैं।

## अगला customization

Business rules के अनुसार salary calculation, monthly attendance closing, overtime rate, leave types, Hindi/English UI, printable A4 reports, Excel export, WhatsApp/SMS notifications, manager assignment और multi-branch support जोड़े जा सकते हैं।
