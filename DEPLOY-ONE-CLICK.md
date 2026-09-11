# One-Click Deployment — CHARNAMRIT STAFF CONTROL

यह package Render Blueprint के लिए तैयार है। Render Blueprint एक YAML file से web service और PostgreSQL database को साथ में provision कर सकता है।

## सबसे आसान तरीका

### Step 1 — GitHub
इस पूरे project folder को एक नया GitHub repository बनाकर उसमें upload करें।

Repository के root में ये files/folders जरूर हों:
- render.yaml
- Dockerfile
- package.json
- server.js
- db/schema.sql
- scripts/migrate.js
- scripts/init-admin.js
- public/

### Step 2 — Render
Render में:
**New → Blueprint**

अपने GitHub repository को Connect करें।

फिर **Deploy Blueprint** दबाएं।

Render `render.yaml` से:
- CHARNAMRIT Staff Control web service
- PostgreSQL database
बनाएगा और DATABASE_URL अपने-आप जोड़ देगा।

### Step 3 — पहली बार secrets
Render पहली Blueprint creation पर ये values पूछेगा:
- ADMIN_NAME
- ADMIN_EMAIL
- ADMIN_PASSWORD

Admin password कम-से-कम 12–16 characters का unique रखें।

### Step 4 — Live
Deploy पूरा होने पर Render एक HTTPS `.onrender.com` URL देगा।

उसी URL से Admin login होगा।

## महत्वपूर्ण
यह production-oriented deployment है और `starter` plan इस्तेमाल करता है। Render के अनुसार Free instances production applications के लिए recommended नहीं हैं। Billing/plan selection Render account में दिखेगा।

## Automatic redeploy
GitHub की linked branch में नया code push होने पर Render automatically redeploy कर सकता है।

## Custom domain
Live होने के बाद Render Dashboard में Custom Domain जोड़कर अपना domain/subdomain लगाया जा सकता है।

उदाहरण:
staff.example.com

## Database
PostgreSQL managed database में रहेगा। Application service database से private connection string के जरिए जुड़ेगी।

## Backup
Business data के लिए managed database backup policy और independent backup strategy जरूर configure करें। Restore test भी करें।

## Security
Live करने से पहले:
- Admin password unique रखें
- HTTPS चालू रखें
- MFA/2FA जोड़ें
- Backup और restore test करें
- Access सिर्फ जरूरत के हिसाब से दें
- Dependencies नियमित update करें
