# BloodLink — Setup Guide (Fixed)

## What was fixed

| Problem | Fix Applied |
|---|---|
| **"Site cannot be reached"** | CORS default now includes port 5500 (VS Code Live Server) and 127.0.0.1. Original only allowed port 5000. |
| **No database data** | Added `seed.js` — run once to populate 10 donors, 5 hospitals, 3 blood requests |
| **No API key protection** | Added `X-API-Key` middleware — all non-public API routes require this header |
| **Missing .env** | Provided `.env` template with all required keys |
| **SMS changed to Fast2SMS** | Replaced Firebase Email OTP with Fast2SMS — sends OTP and donor alerts directly to mobile numbers via SMS |

---

## Step 1 — MongoDB Setup (Free, 5 minutes)

1. Go to **https://cloud.mongodb.com** → Sign up free
2. Create a **free M0 cluster** (choose any region)
3. **Database Access** → Add database user (save username + password)
4. **Network Access** → Add IP address → `0.0.0.0/0` (allow all)
5. **Connect** → Drivers → copy the connection string

It looks like:
```
mongodb+srv://myuser:mypassword@cluster0.abc123.mongodb.net/?retryWrites=true&w=majority
```

---

## Step 2 — Configure .env

Place the `.env` file inside your `backend/` folder and fill in:

```env
MONGO_URI=mongodb+srv://myuser:mypassword@cluster0.abc123.mongodb.net/bloodlink?retryWrites=true&w=majority

JWT_SECRET=paste_a_random_64_character_string_here

API_KEY=paste_another_random_32_character_string_here

FAST2SMS_API_KEY=paste_your_fast2sms_api_key_here
```

Generate secrets instantly:
```bash
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```
Run twice — once for JWT_SECRET, once for API_KEY.

---

## Step 2B — Fast2SMS Setup (~5 minutes)

Fast2SMS delivers OTP and blood-request alert SMS directly to any Indian mobile number.

1. Go to **https://www.fast2sms.com** → Sign up free (you get ₹50 credit instantly)
2. Go to **Dashboard → Dev API** → copy your **API Key**
3. Paste it into `.env`:

```env
FAST2SMS_API_KEY=your_api_key_from_dashboard
```

> **Notes:**
> - The **Quick SMS (q) route** is used — no DLT template registration needed for development/testing.
> - For production, register a DLT-approved template on the Fast2SMS dashboard and switch to the transactional route.
> - Only **Indian 10-digit mobile numbers** are supported (country code `+91` is stripped automatically).
> - Free ₹50 credit gives roughly 100–200 SMS. Recharge plans start at ₹199 (~1000 SMS).
> - OTP SMS text: *"Your BloodLink OTP is XXXXXX. Valid for 10 minutes. Do not share with anyone."*

---



```bash
cd backend
npm install
node seed.js       ← Creates all demo data in MongoDB
node server.js     ← Start the server
```

You should see:
```
✅ MongoDB connected
🩸  BloodLink  →  http://0.0.0.0:5000
```

---

## Step 4 — Open the frontend

In VS Code → right-click `frontend/index.html` → **Open with Live Server**

Opens at `http://127.0.0.1:5500` ✅ (now allowed by CORS)

---

## Demo Login Credentials

| Role | Email | Password |
|---|---|---|
| Admin | admin@bloodlink.in | admin123 |
| Donor (any of 10) | arjun@demo.com | donor123 |
| Hospital (any of 5) | apollo.chennai@demo.com | hospital123 |

---

## Using the API Key in your frontend (api.js)

Add this header to all your `fetch()` calls in `frontend/js/api.js`:

```javascript
const API_KEY = 'paste_your_api_key_here';  // same as API_KEY in .env

// Example fetch with API key:
const res = await fetch('http://localhost:5000/api/admin/stats', {
  headers: {
    'Authorization': `Bearer ${token}`,
    'X-API-Key': API_KEY,
    'Content-Type': 'application/json',
  }
});
```

**Public routes that do NOT need the API key** (already open):
- `POST /api/auth/login`
- `POST /api/auth/register/donor`
- `POST /api/auth/register/hospital`
- `POST /api/emergency/otp/request`  ← sends OTP via Fast2SMS SMS
- `POST /api/emergency/otp/verify`
- `GET  /api/health`
- `GET  /api/donors/map`
- `GET  /api/hospitals/map`

---

## File Checklist

```
backend/
├── server.js       ← Use the fixed version provided
├── seed.js         ← Run once to populate database
├── package.json    ← Unchanged
└── .env            ← Fill in your keys (NEVER commit to Git!)
```

Add to `.gitignore`:
```
.env
node_modules/
uploads/
bloodlink.db
```
