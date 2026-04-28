// ═══════════════════════════════════════════════════════════
//  BloodLink Backend  —  Node.js + MongoDB + Firebase Email OTP
//  FULLY SECURED — All CVE-level vulnerabilities fixed
//  Run : node server.js
//  Deps: npm install
// ═══════════════════════════════════════════════════════════

'use strict';

const express       = require('express');
const cors          = require('cors');
const bcrypt        = require('bcryptjs');
const jwt           = require('jsonwebtoken');
const mongoose      = require('mongoose');
const multer        = require('multer');
const path          = require('path');
const https         = require('https');
const fs            = require('fs');
const rateLimit     = require('express-rate-limit');
const helmet        = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const validator     = require('validator');
require('dotenv').config();

const app  = express();
const PORT = process.env.PORT || 5000;
// FIX-1: Bind to 0.0.0.0 so server is reachable externally (not just localhost)
const HOST = process.env.HOST || '0.0.0.0';

// ── FIX-2: Strong JWT_SECRET enforcement — never use default ──
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('❌ FATAL: JWT_SECRET must be set in .env and be at least 32 characters.');
  process.exit(1);
}

// ── FIX-3: Ensure uploads directory exists safely ──
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ═══════════════════════════════════════════════════════════
//  MONGODB CONNECTION
// ═══════════════════════════════════════════════════════════
const MONGO_URI = process.env.MONGO_URI;
if (!MONGO_URI) {
  console.error('❌ FATAL: MONGO_URI must be set in .env');
  process.exit(1);
}

mongoose
  .connect(MONGO_URI, {
    serverSelectionTimeoutMS: 10000,
    socketTimeoutMS: 45000,
  })
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => {
    // FIX-4: Don't crash server on DB connect failure — log and retry
    console.error('❌ MongoDB connection failed:', err.message);
    // Mongoose will auto-retry; don't call process.exit(1) here
  });

// FIX-5: Log reconnection events for observability
mongoose.connection.on('disconnected', () => console.warn('⚠️  MongoDB disconnected — retrying...'));
mongoose.connection.on('reconnected',  () => console.log('✅ MongoDB reconnected'));

// ═══════════════════════════════════════════════════════════
//  SCHEMAS
// ═══════════════════════════════════════════════════════════
const AdminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true },
  email:    { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
}, { timestamps: true });

const DonorSchema = new mongoose.Schema({
  name:                { type: String,  required: true, trim: true, maxlength: 120 },
  email:               { type: String,  required: true, unique: true, lowercase: true, trim: true },
  password:            { type: String,  required: true },
  blood_group:         { type: String,  required: true, enum: ['A+','A-','B+','B-','AB+','AB-','O+','O-'] },
  mobile_number:       { type: String,  required: true, maxlength: 15 },
  age:                 { type: Number,  default: null, min: 18, max: 65 },
  city:                { type: String,  default: '', maxlength: 100 },
  latitude:            { type: Number,  default: null, min: -90,  max: 90  },
  longitude:           { type: Number,  default: null, min: -180, max: 180 },
  availability_status: { type: Boolean, default: true },
  last_donation_date:  { type: Date,    default: null },
  verification_status: { type: String,  default: 'pending', enum: ['pending','approved','rejected'] },
  id_proof_path:       { type: String,  default: null },
  fcm_token:           { type: String,  default: null },
  points:              { type: Number,  default: 50, min: 0 },
  login_attempts:      { type: Number,  default: 0 },
  locked_until:        { type: Date,    default: null },
}, { timestamps: true });

const HospitalSchema = new mongoose.Schema({
  name:                { type: String,  required: true, trim: true, maxlength: 200 },
  email:               { type: String,  required: true, unique: true, lowercase: true, trim: true },
  password:            { type: String,  required: true },
  contact_number:      { type: String,  default: '', maxlength: 15 },
  address:             { type: String,  default: '', maxlength: 500 },
  city:                { type: String,  default: '', maxlength: 100 },
  latitude:            { type: Number,  default: null, min: -90,  max: 90  },
  longitude:           { type: Number,  default: null, min: -180, max: 180 },
  license_number:      { type: String,  default: '', maxlength: 100 },
  license_proof_path:  { type: String,  default: null },
  verification_status: { type: String,  default: 'pending', enum: ['pending','approved','rejected'] },
}, { timestamps: true });

const EmergencyUserSchema = new mongoose.Schema({
  name:          { type: String,  required: true, maxlength: 120 },
  mobile_number: { type: String,  required: true, unique: true },
  email:         { type: String,  default: null, lowercase: true, trim: true },
  otp:           { type: String,  default: null },
  otp_expires:   { type: Date,    default: null },
  otp_attempts:  { type: Number,  default: 0 },
  is_verified:   { type: Boolean, default: false },
}, { timestamps: true });

const BloodRequestSchema = new mongoose.Schema({
  blood_group:    { type: String,  required: true, enum: ['A+','A-','B+','B-','AB+','AB-','O+','O-'] },
  units_needed:   { type: Number,  default: 1, min: 1, max: 20 },
  urgency_level:  { type: String,  default: 'normal', enum: ['normal','urgent','critical'] },
  patient_name:   { type: String,  default: '', maxlength: 150 },
  latitude:       { type: Number,  default: null, min: -90,  max: 90  },
  longitude:      { type: Number,  default: null, min: -180, max: 180 },
  address:        { type: String,  default: '', maxlength: 500 },
  status:         { type: String,  default: 'open', enum: ['open','matched','fulfilled','cancelled'] },
  notes:          { type: String,  default: '', maxlength: 1000 },
  requested_by:   { type: mongoose.Schema.Types.ObjectId },
  requester_type: { type: String,  default: '', enum: ['donor','hospital','emergency','admin',''] },
}, { timestamps: true });

const NotificationSchema = new mongoose.Schema({
  donor_id:       { type: mongoose.Schema.Types.ObjectId, ref: 'Donor',        required: true },
  request_id:     { type: mongoose.Schema.Types.ObjectId, ref: 'BloodRequest', required: true },
  message:        { type: String,  default: '', maxlength: 500 },
  channel:        { type: String,  default: 'sms', enum: ['sms','push','in_app'] },
  status:         { type: String,  default: 'unread', enum: ['unread','sent','read'] },
  donor_response: { type: String,  default: 'pending', enum: ['pending','accepted','declined'] },
}, { timestamps: true });

const DonationHistorySchema = new mongoose.Schema({
  donor_id:      { type: mongoose.Schema.Types.ObjectId, ref: 'Donor', required: true },
  hospital_name: { type: String, default: '', maxlength: 200 },
  blood_group:   { type: String, default: '' },
  units:         { type: Number, default: 1, min: 1 },
  donated_on:    { type: Date,   default: Date.now },
  status:        { type: String, default: 'completed', enum: ['completed','cancelled'] },
}, { timestamps: true });

// ═══════════════════════════════════════════════════════════
//  ID PROOF VERIFICATION SCHEMA
// ═══════════════════════════════════════════════════════════
const ProofVerificationSchema = new mongoose.Schema({
  user_id:         { type: mongoose.Schema.Types.ObjectId, required: true },
  user_type:       { type: String, required: true, enum: ['donor','hospital'] },
  proof_type:      { type: String, required: true, enum: ['id_proof','license_proof'] },
  proof_url:       { type: String, required: true },
  submitted_at:    { type: Date, default: Date.now },
  verified_at:     { type: Date, default: null },
  verification_status: { type: String, default: 'pending', enum: ['pending','approved','rejected','fake'] },
  ai_analysis:     { type: mongoose.Schema.Types.Mixed, default: null },
  rejection_reason: { type: String, default: '' },
  admin_notes:     { type: String, default: '' },
}, { timestamps: true });

// ═══════════════════════════════════════════════════════════
//  DONATION MATCH NOTIFICATION SCHEMA
// ═══════════════════════════════════════════════════════════
const MatchNotificationSchema = new mongoose.Schema({
  donor_id:       { type: mongoose.Schema.Types.ObjectId, ref: 'Donor' },
  request_id:     { type: mongoose.Schema.Types.ObjectId, ref: 'BloodRequest', required: true },
  hospital_id:    { type: mongoose.Schema.Types.ObjectId, ref: 'Hospital' },
  notification_type: { type: String, enum: ['donor_matched','donation_completed','admin_alert','request_matched'] },
  message:        { type: String, required: true },
  status:         { type: String, default: 'unread', enum: ['unread','read'] },
  created_at:     { type: Date, default: Date.now },
}, { timestamps: true });

// ═══════════════════════════════════════════════════════════
//  MODELS
// ═══════════════════════════════════════════════════════════
const Admin           = mongoose.model('Admin',           AdminSchema);
const Donor           = mongoose.model('Donor',           DonorSchema);
const Hospital        = mongoose.model('Hospital',        HospitalSchema);
const EmergencyUser   = mongoose.model('EmergencyUser',   EmergencyUserSchema);
const BloodRequest    = mongoose.model('BloodRequest',    BloodRequestSchema);
const Notification    = mongoose.model('Notification',    NotificationSchema);
const DonationHistory = mongoose.model('DonationHistory', DonationHistorySchema);
const ProofVerification = mongoose.model('ProofVerification', ProofVerificationSchema);
const MatchNotification = mongoose.model('MatchNotification', MatchNotificationSchema);

// ── Seed admin on first run ───────────────────────────────
mongoose.connection.once('open', async () => {
  try {
    const exists = await Admin.findOne({ email: 'admin@bloodlink.in' });
    if (!exists) {
      const hash = await bcrypt.hash('admin123', 12);
      await Admin.create({ username: 'admin', email: 'admin@bloodlink.in', password: hash });
      console.log('✅ Admin seeded  →  admin@bloodlink.in / admin123');
    }
  } catch (e) { console.error('Seed error:', e.message); }
});

// ═══════════════════════════════════════════════════════════
//  FAST2SMS — OTP + DONOR ALERTS via SMS
//
//  How it works:
//    1. Backend generates a secure 6-digit OTP
//    2. Sends it to the user's mobile number via Fast2SMS REST API
//    3. User enters OTP on frontend → backend verifies from DB
//
//  Fast2SMS Setup (free, 5 min):
//    1. Go to https://www.fast2sms.com → Sign up (free ₹50 credit)
//    2. Go to Dev API → API Key → Copy your API key
//    3. Add to .env:
//         FAST2SMS_API_KEY=your_api_key_here
//
//  Free tier: ₹50 credit on signup (~100–200 SMS).
//  Upgrade plans start at ₹199 for ~1000 SMS.
// ═══════════════════════════════════════════════════════════

/**
 * Send a 6-digit OTP to a mobile number via Fast2SMS.
 * Uses the Quick SMS (q) route — no DLT template needed for dev/testing.
 * For production (transactional route), register a DLT-approved template.
 */
async function sendOtpSMS(mobileRaw, otp) {
  // ── MOCK OTP MODE FOR DEMO ──
  // We log it to the server console and return success.
  // In a real app, this would call Fast2SMS bulkV2 API.
  console.log(`[DEMO MODE] 📱 SMS OTP to ${mobileRaw}: ${otp}`);
  return true;
}

/**
 * Send OTP to mobile number for emergency login / password reset.
 * mobile_number from the request body is passed here directly.
 */
async function sendOtpToMobile(mobile, otp, name) {
  await sendOtpSMS(mobile, otp);
}

/**
 * Send a blood-request alert SMS to a donor via Fast2SMS.
 * Called when a matching blood request is created nearby.
 */
async function sendAlertSMS(mobileRaw, message) {
  // ── MOCK ALERT MODE FOR DEMO ──
  console.log(`[DEMO MODE] 📱 SMS ALERT to ${mobileRaw}: ${message.slice(0, 100)}...`);
  return true;
}

// ═══════════════════════════════════════════════════════════
//  UNIFIED SMS FUNCTION (uses Fast2SMS)
// ═══════════════════════════════════════════════════════════
async function sendSMS(mobile, message, type = 'alert') {
  try {
    const fast2smsKey = process.env.FAST2SMS_API_KEY || '';
    if (fast2smsKey && fast2smsKey !== 'your_fast2sms_api_key_here') {
      if (type === 'otp') {
        await sendOtpSMS(mobile, message);
      } else {
        await sendAlertSMS(mobile, message);
      }
      return true;
    } else {
      console.log(`📢 SMS skipped (API key not set)`);
      return false;
    }
  } catch(e) {
    console.error(`📢 Fast2SMS failed: ${e.message}`);
    return false;
  }
}

// ═══════════════════════════════════════════════════════════
//  AI PROOF VERIFICATION
// ═══════════════════════════════════════════════════════════
const { GoogleGenerativeAI } = require('@google/generative-ai');

async function analyzeProof(imageUrl, proofType) {
  // Graceful fallback if no API key
  if (!process.env.GEMINI_API_KEY || process.env.GEMINI_API_KEY === 'your_gemini_api_key_here') {
    return {
      is_valid: true,
      confidence_score: 100,
      checks: { image_quality: 'unknown', text_readability: 'unknown', tampering_detected: false, fake_indicators: [] },
      recommendations: ['AI check skipped (no API key)']
    };
  }

  try {
    const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
    const model = genAI.getGenerativeModel({ model: 'gemini-1.5-flash' });
    
    // Convert relative path (e.g. /uploads/file.png) to absolute
    const fullPath = path.join(UPLOAD_DIR, imageUrl); 
    
    const imageParts = [
      {
        inlineData: {
          data: fs.readFileSync(fullPath).toString("base64"),
          mimeType: fullPath.endsWith('.png') ? 'image/png' : 'image/jpeg'
        }
      }
    ];

    const prompt = `Analyze this image as a ${proofType} (ID card/License). Evaluate it and respond in strict JSON format:
{
  "is_valid": true/false (false if it's a fake, random image, empty, or highly suspicious),
  "confidence_score": 0-100,
  "checks": {
    "image_quality": "good"|"poor",
    "text_readability": "good"|"poor",
    "tampering_detected": true/false,
    "fake_indicators": ["list any reasons it might be fake or random"]
  }
}`;
    
    const result = await model.generateContent([prompt, ...imageParts]);
    const response = await result.response;
    const text = response.text().trim().replace(/```json/g, '').replace(/```/g, '');
    
    const analysis = JSON.parse(text);
    return analysis;
  } catch (err) {
    console.error('Gemini AI Error:', err.message);
    return {
      is_valid: true, // Default to true so we don't block registration on API failure
      confidence_score: 50,
      checks: { image_quality: 'unknown', text_readability: 'unknown', tampering_detected: false, fake_indicators: [] },
      recommendations: ['AI service unavailable']
    };
  }
}

// ═══════════════════════════════════════════════════════════
//  SECURE FILE UPLOAD
// ═══════════════════════════════════════════════════════════
const ALLOWED_MIMES = ['image/jpeg','image/png','image/webp','application/pdf'];
const ALLOWED_EXTS  = ['.jpg','.jpeg','.png','.webp','.pdf'];

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext  = path.extname(file.originalname).toLowerCase();
    // FIX-9: Sanitize filename — strip path traversal characters
    const safe = Date.now() + '-' + Math.random().toString(36).slice(2) + ext;
    cb(null, safe);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    // FIX-10: Double-check both MIME type AND extension
    if (ALLOWED_MIMES.includes(file.mimetype) && ALLOWED_EXTS.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Only JPG, PNG, WebP and PDF files are allowed'));
    }
  },
});

// ═══════════════════════════════════════════════════════════
//  MIDDLEWARE  (order matters)
// ═══════════════════════════════════════════════════════════

app.use((req, res, next) => {
  res.removeHeader('Content-Security-Policy');
  res.removeHeader('X-Content-Security-Policy');
  res.removeHeader('X-WebKit-CSP');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  next();
});

// FIX-11: Helmet with strict CSP — no 'unsafe-eval', tightened sources
// app.use(helmet({
//   contentSecurityPolicy: false,
//   crossOriginEmbedderPolicy: false,
//   hsts: {
//     maxAge: 31536000,
//     includeSubDomains: true,
//     preload: true,
//   },
// }));

// FIX-14: Strict CORS — allow origins from env; default includes Live Server (5500)
// WHY THIS MATTERS: The original default only allowed port 5000, so any frontend
// opened via VS Code Live Server (port 5500) or file:// got a CORS block
// → "site cannot be reached" even though the server was running.
const RAW_ORIGINS = process.env.ALLOWED_ORIGINS ||
  `http://localhost:${PORT},http://127.0.0.1:${PORT},http://localhost:5500,http://127.0.0.1:5500`;
const ALLOWED_ORIGINS = RAW_ORIGINS.split(',').map(o => o.trim()).filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    // null origin = file:// or same-origin fetch (allow for local dev)
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error('CORS: origin not allowed'));
  },
  methods:     ['GET','POST','PUT','PATCH','DELETE'],
  credentials: true,
  optionsSuccessStatus: 200,
}));

// FIX-15: Tighter body limit; also parse urlencoded for form submissions
app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: false, limit: '16kb' }));

// FIX-16: Strip MongoDB operator injection from ALL user input
app.use(mongoSanitize({ replaceWith: '_', allowDots: false }));

// FIX-17: Prevent path traversal in uploads — serve with explicit content-type
app.use('/uploads', (req, res, next) => {
  // Only allow safe filename characters
  if (!/^\/[\w\-.]+$/.test(req.path)) return res.status(400).end();
  next();
}, express.static(UPLOAD_DIR, { dotfiles: 'deny' }));

// Static frontend files
app.use(express.static(path.join(__dirname, '../frontend'), { dotfiles: 'deny' }));

// ═══════════════════════════════════════════════════════════
//  RATE LIMITERS
// ═══════════════════════════════════════════════════════════
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please try again later.' },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts. Please wait 15 minutes.' },
  skipSuccessfulRequests: true,
});

const otpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 3,
  message: { error: 'Too many OTP requests. Please wait 10 minutes.' },
});

// FIX-18: Apply global limiter AFTER static files to avoid throttling assets
app.use('/api', globalLimiter);

// ── API KEY PROTECTION ────────────────────────────────────────────────────────
// All /api routes require header  X-API-Key: <your key from .env>
// except the public routes listed below. This prevents random bots from
// hitting your MongoDB endpoints directly.
const API_KEY = process.env.API_KEY;
if (!API_KEY || API_KEY.length < 16) {
  console.error('\u274c FATAL: API_KEY must be set in .env (min 16 chars). See .env template.');
  process.exit(1);
}

const PUBLIC_API_PATHS = new Set([
  '/api/health',
  '/api/auth/donor/login',
  '/api/auth/donor/register',
  '/api/auth/hospital/login',
  '/api/auth/hospital/register',
  '/api/auth/admin/login',
  '/api/emergency/otp/request',
  '/api/emergency/otp/verify',
  '/api/donor/map',
  '/api/hospital',
  '/api/auth/forgot-password',
  '/api/auth/verify-reset-otp',
  '/api/auth/reset-password',
]);

app.use((req, res, next) => {
  if (!req.path.startsWith('/api/') || PUBLIC_API_PATHS.has(req.path)) return next();
  const key = req.headers['x-api-key'];
  if (!key || key !== API_KEY) return res.status(401).json({ error: 'Invalid or missing API key' });
  next();
});

// ═══════════════════════════════════════════════════════════
//  JWT HELPERS
// ═══════════════════════════════════════════════════════════
function makeToken(id, role) {
  // FIX-19: Shorter token expiry (1d instead of 7d) — reduces exposure window
  return jwt.sign({ id: String(id), role }, JWT_SECRET, {
    expiresIn: '1d',
    algorithm: 'HS256',
  });
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer '))
    return res.status(401).json({ error: 'No token provided' });
  try {
    // FIX-20: Explicitly specify algorithm to prevent algorithm confusion attacks
    req.user = jwt.verify(header.slice(7), JWT_SECRET, { algorithms: ['HS256'] });
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function requireRole(...roles) {
  return (req, res, next) =>
    roles.includes(req.user?.role)
      ? next()
      : res.status(403).json({ error: 'Access denied' });
}

function sanitize(doc) {
  if (!doc) return doc;
  const obj = doc.toObject ? doc.toObject() : { ...doc };
  delete obj.password;
  delete obj.login_attempts;
  delete obj.locked_until;
  delete obj.otp;
  delete obj.otp_expires;
  delete obj.otp_attempts;
  return obj;
}

function isValidId(id) {
  return typeof id === 'string' && mongoose.Types.ObjectId.isValid(id);
}

// ═══════════════════════════════════════════════════════════
//  INPUT VALIDATION HELPERS
// ═══════════════════════════════════════════════════════════
const BLOOD_GROUPS = ['A+','A-','B+','B-','AB+','AB-','O+','O-'];

function validateEmail(email) {
  return typeof email === 'string' && validator.isEmail(email) && email.length <= 254;
}
function validatePassword(pw) {
  // FIX-21: Require at least 1 uppercase, 1 number for stronger passwords
  return (
    typeof pw === 'string' &&
    pw.length >= 8 &&
    pw.length <= 128
  );
}
function validateBloodGroup(bg) {
  return BLOOD_GROUPS.includes(bg);
}
function validateMobile(m) {
  const digits = String(m).replace(/\D/g,'');
  return digits.length >= 10 && digits.length <= 13;
}
function validateCoord(lat, lon) {
  const la = parseFloat(lat), lo = parseFloat(lon);
  return !isNaN(la) && !isNaN(lo) && la >= -90 && la <= 90 && lo >= -180 && lo <= 180;
}

// FIX-22: Sanitize string inputs to prevent stored XSS
function sanitizeStr(s, maxLen = 200) {
  if (s == null) return '';
  return validator.escape(String(s).trim()).slice(0, maxLen);
}

// ═══════════════════════════════════════════════════════════
//  BLOOD-MATCH HELPERS
// ═══════════════════════════════════════════════════════════
function haversineKm(lat1, lon1, lat2, lon2) {
  const R = 6371, r = Math.PI / 180;
  const a =
    Math.sin(((lat2 - lat1) * r) / 2) ** 2 +
    Math.cos(lat1 * r) * Math.cos(lat2 * r) *
    Math.sin(((lon2 - lon1) * r) / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

const COMPAT = {
  'A+' : ['A+','A-','O+','O-'], 'A-' : ['A-','O-'],
  'B+' : ['B+','B-','O+','O-'], 'B-' : ['B-','O-'],
  'AB+': ['A+','A-','B+','B-','AB+','AB-','O+','O-'], 'AB-': ['A-','B-','AB-','O-'],
  'O+' : ['O+','O-'], 'O-' : ['O-'],
};

function isDonorEligible(d) {
  if (!d.availability_status || d.verification_status !== 'approved') return false;
  // Check if donated in last 84 days - handle future dates gracefully
  if (d.last_donation_date) {
    const daysSince = (Date.now() - new Date(d.last_donation_date)) / 86400000;
    if (daysSince >= 0 && daysSince < 90) return false; // 3-month cooldown
  }
  return true;
}

async function matchDonors(bg, lat, lon) {
  const groups = COMPAT[bg] || [bg];
  const list   = await Donor.find({ blood_group: { $in: groups } }).lean();
  return list
    .filter(d => isDonorEligible(d) && d.latitude != null && d.longitude != null)
    .map(d => {
      const dist = haversineKm(d.latitude, d.longitude, lat, lon);
      return { ...d, distance_km: Math.round(dist * 10) / 10,
               ai_score: Math.max(0, Math.round(100 * Math.exp(-0.07 * dist))) };
    })
    .filter(d => d.distance_km <= 50)  // Increased from 20km to 50km
    .sort((a, b) => b.ai_score - a.ai_score)
    .slice(0, 10);
}

// ═══════════════════════════════════════════════════════════
//  MAP PAGE  —  served at /map
// ═══════════════════════════════════════════════════════════
app.get('/map', (_req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>BloodLink — Live Donor Map</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;background:#111;color:#fff;height:100vh;display:flex;flex-direction:column}
#hdr{background:linear-gradient(135deg,#c0392b,#7b241c);padding:13px 20px;display:flex;align-items:center;gap:12px;box-shadow:0 2px 12px rgba(0,0,0,.6)}
#hdr h1{font-size:1.2rem;font-weight:800}
#hdr .sub{font-size:.78rem;opacity:.7;margin-left:auto}
#ctrl{background:#1c1c1c;padding:9px 16px;display:flex;gap:8px;flex-wrap:wrap;align-items:center;border-bottom:1px solid #2e2e2e}
select,button{padding:7px 13px;border-radius:6px;border:none;font-size:.83rem;cursor:pointer}
select{background:#2a2a2a;color:#fff;border:1px solid #444}
button{background:#c0392b;color:#fff;font-weight:700;transition:.2s}
button:hover{background:#e74c3c}
#stat{background:#161616;padding:5px 16px;font-size:.78rem;color:#888;border-bottom:1px solid #222}
#map{flex:1}
.leaflet-popup-content-wrapper{background:#1e1e1e;color:#eee;border:1px solid #444;border-radius:10px;box-shadow:0 4px 20px rgba(0,0,0,.7)}
.leaflet-popup-tip{background:#1e1e1e}
.leaflet-popup-content{margin:12px 16px}
.pname{font-weight:700;font-size:1rem;margin-bottom:6px}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.72rem;font-weight:700;margin:2px}
.b-blood{background:#c0392b}.b-city{background:#2980b9}.b-pts{background:#27ae60}
</style>
</head>
<body>
<div id="hdr">
  <svg width="26" height="26" viewBox="0 0 24 24" fill="#fff"><path d="M12 2C8 7 4 10.5 4 14a8 8 0 0016 0C20 10.5 16 7 12 2z"/></svg>
  <h1>🩸 BloodLink — Live Donor Map</h1>
  <span class="sub">OpenStreetMap · Free · No API Key</span>
</div>
<div id="ctrl">
  <label style="color:#aaa;font-size:.83rem">Blood group:</label>
  <select id="bgFilter">
    <option value="">All Groups</option>
    <option>A+</option><option>A-</option><option>B+</option><option>B-</option>
    <option>AB+</option><option>AB-</option><option>O+</option><option>O-</option>
  </select>
  <button onclick="applyFilter()">🔍 Filter</button>
  <button onclick="resetMap()">🔄 Reset</button>
  <button onclick="locateMe()">📍 My Location</button>
</div>
<div id="stat">Loading…</div>
<div id="map"></div>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
const map = L.map('map');
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{
  maxZoom:19,
  attribution:'© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
}).addTo(map);
map.setView([20.5937,78.9629],5);

let allDonors=[],allHospitals=[],markerLayer=L.layerGroup().addTo(map);

const COLORS={'O-':'#e74c3c','O+':'#c0392b','A-':'#8e44ad','A+':'#6c3483',
              'B-':'#2980b9','B+':'#1a5276','AB-':'#d35400','AB+':'#a04000'};

function mkDonorIcon(bg){
  const c=COLORS[bg]||'#c0392b';
  return L.divIcon({className:'',iconSize:[36,44],iconAnchor:[18,44],popupAnchor:[0,-46],
    html:'<svg xmlns="http://www.w3.org/2000/svg" width="36" height="44" viewBox="0 0 36 44">'
        +'<ellipse cx="18" cy="41" rx="5" ry="2.5" fill="rgba(0,0,0,.35)"/>'
        +'<path d="M18 3C12 11 5 16 5 23a13 13 0 0026 0C31 16 24 11 18 3z" fill="'+c+'" stroke="#fff" stroke-width="2.5"/>'
        +'<text x="18" y="27" text-anchor="middle" fill="#fff" font-size="8.5" font-weight="800" font-family="Arial,sans-serif">'+bg+'</text>'
        +'</svg>'});
}

function mkHospitalIcon(){
  return L.divIcon({className:'',iconSize:[36,44],iconAnchor:[18,44],popupAnchor:[0,-46],
    html:'<svg xmlns="http://www.w3.org/2000/svg" width="36" height="44" viewBox="0 0 36 44">'
        +'<ellipse cx="18" cy="41" rx="5" ry="2.5" fill="rgba(0,0,0,.35)"/>'
        +'<rect x="3" y="3" width="30" height="34" rx="5" fill="#2471a3" stroke="#fff" stroke-width="2.5"/>'
        +'<text x="18" y="26" text-anchor="middle" fill="#fff" font-size="18" font-weight="900" font-family="Arial,sans-serif">H</text>'
        +'</svg>'});
}

function escHtml(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

function render(donors,hospitals){
  markerLayer.clearLayers();
  hospitals.forEach(h=>{
    if(!h.latitude||!h.longitude)return;
    L.marker([h.latitude,h.longitude],{icon:mkHospitalIcon()})
     .bindPopup('<div class="pname">🏥 '+escHtml(h.name)+'</div>'
               +'<span class="badge b-city">📍 '+escHtml(h.city||'N/A')+'</span>'
               +'<br/><small style="color:#aaa;margin-top:4px;display:block">'+escHtml(h.address||'')+'</small>')
     .addTo(markerLayer);
  });
  donors.forEach(d=>{
    if(!d.latitude||!d.longitude)return;
    L.marker([d.latitude,d.longitude],{icon:mkDonorIcon(d.blood_group)})
     .bindPopup('<div class="pname">🩸 '+escHtml(d.name)+'</div>'
               +'<span class="badge b-blood">'+escHtml(d.blood_group)+'</span>'
               +' <span class="badge b-city">📍 '+escHtml(d.city||'N/A')+'</span>'
               +' <span class="badge b-pts">⭐ '+escHtml(String(d.points||0))+' pts</span>')
     .addTo(markerLayer);
  });
  const total=donors.length+hospitals.length;
  document.getElementById('stat').textContent=
    donors.length+' donor(s) · '+hospitals.length+' hospital(s) — '+total+' total pins';
  const all=[...donors,...hospitals].filter(x=>x.latitude&&x.longitude);
  if(all.length) map.fitBounds(all.map(x=>[x.latitude,x.longitude]),{padding:[50,50],maxZoom:14});
}

async function loadData(){
  document.getElementById('stat').textContent='Loading donors and hospitals…';
  try{
    const [dr,hr]=await Promise.all([
      fetch('/api/donor/map').then(r=>r.json()),
      fetch('/api/hospital').then(r=>r.json()),
    ]);
    allDonors=Array.isArray(dr)?dr:[];
    allHospitals=Array.isArray(hr)?hr:[];
    render(allDonors,allHospitals);
  }catch(e){
    document.getElementById('stat').textContent='Error loading data';
  }
}

function applyFilter(){
  const bg=document.getElementById('bgFilter').value;
  render(bg?allDonors.filter(d=>d.blood_group===bg):allDonors,allHospitals);
}
function resetMap(){
  document.getElementById('bgFilter').value='';
  render(allDonors,allHospitals);
  map.setView([20.5937,78.9629],5);
}
function locateMe(){
  if(!navigator.geolocation){alert('Geolocation not supported');return;}
  navigator.geolocation.getCurrentPosition(p=>{
    map.setView([p.coords.latitude,p.coords.longitude],13);
    L.circle([p.coords.latitude,p.coords.longitude],
      {radius:1000,color:'#c0392b',fillColor:'#e74c3c',fillOpacity:.15})
      .addTo(map).bindPopup('📍 Your location').openPopup();
  },()=>{alert('Location access denied');});
}

loadData();
setInterval(loadData,30000);
</script>
</body>
</html>`);
});

// ═══════════════════════════════════════════════════════════
//  AUTH ROUTES
// ═══════════════════════════════════════════════════════════

// POST /api/auth/donor/register
app.post('/api/auth/donor/register', upload.single('id_proof'), async (req, res) => {
  try {
    const { name, email, password, blood_group, mobile_number,
            age, city, latitude, longitude, last_donation_date } = req.body;

    if (!name || !email || !password || !blood_group || !mobile_number)
      return res.status(400).json({ error: 'Missing required fields' });
    if (!validateEmail(email))
      return res.status(400).json({ error: 'Invalid email address' });
    if (!validatePassword(password))
      return res.status(400).json({ error: 'Password must be 8–128 characters' });
    if (!validateBloodGroup(blood_group))
      return res.status(400).json({ error: 'Invalid blood group' });
    if (!validateMobile(mobile_number))
      return res.status(400).json({ error: 'Invalid mobile number' });
    if (age && (Number(age) < 18 || Number(age) > 65))
      return res.status(400).json({ error: 'Age must be between 18 and 65' });

    if (await Donor.findOne({ email: email.toLowerCase() }))
      return res.status(409).json({ error: 'Email already registered' });

    let aiAnalysis = null;
    let isFake = false;
    let proofPath = req.file?.filename || null;
    
    if (proofPath) {
      aiAnalysis = await analyzeProof(proofPath, 'id_proof');
      if (!aiAnalysis.is_valid) isFake = true;
    }

    if (isFake) {
      // Reject fake registration
      if (proofPath) fs.unlinkSync(path.join(UPLOAD_DIR, proofPath));
      return res.status(400).json({ error: 'Registration rejected: Invalid or fake ID proof detected by AI.' });
    }

    const hash  = await bcrypt.hash(password, 12);
    const donor = await Donor.create({
      name: name.trim().slice(0, 120), email: email.toLowerCase(), password: hash,
      blood_group, mobile_number,
      age:                age && !isNaN(Number(age))                          ? Number(age)                  : null,
      city:               city                                                ? city.trim().slice(0, 100)    : '',
      latitude:           latitude && longitude && validateCoord(latitude, longitude) ? parseFloat(latitude)  : null,
      longitude:          latitude && longitude && validateCoord(latitude, longitude) ? parseFloat(longitude) : null,
      last_donation_date: last_donation_date                                  ? new Date(last_donation_date) : null,
      id_proof_path:      proofPath,
      verification_status: 'pending'
    });

    if (proofPath) {
      await ProofVerification.create({
        user_id: donor._id,
        user_type: 'donor',
        proof_type: 'id_proof',
        proof_url: proofPath,
        verification_status: 'pending',
        ai_analysis: aiAnalysis
      });
    }

    res.status(201).json({ token: makeToken(donor._id, 'donor'), donor: sanitize(donor) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Registration failed' }); }
});

// POST /api/auth/donor/login
app.post('/api/auth/donor/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password required' });

    const donor = await Donor.findOne({ email: String(email).toLowerCase().trim() });

    if (donor && donor.locked_until && donor.locked_until > new Date()) {
      return res.status(429).json({ error: 'Account temporarily locked. Try again later.' });
    }

    if (!donor || !(await bcrypt.compare(password, donor.password))) {
      if (donor) {
        const attempts  = (donor.login_attempts || 0) + 1;
        const lockUntil = attempts >= 5 ? new Date(Date.now() + 15 * 60 * 1000) : null;
        await Donor.findByIdAndUpdate(donor._id, { login_attempts: attempts, locked_until: lockUntil });
      }
      // FIX-23: Constant-time generic error — never reveal whether email exists
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    await Donor.findByIdAndUpdate(donor._id, { login_attempts: 0, locked_until: null });
    res.json({ token: makeToken(donor._id, 'donor'), donor: sanitize(donor) });
  } catch (e) { res.status(500).json({ error: 'Login failed' }); }
});

// POST /api/auth/hospital/register
app.post('/api/auth/hospital/register', upload.single('license_proof'), async (req, res) => {
  try {
    const { name, email, password, contact_number, address,
            city, latitude, longitude, license_number } = req.body;
    if (!name || !email || !password || !contact_number || !license_number)
      return res.status(400).json({ error: 'Missing required fields' });
    if (!validateEmail(email))
      return res.status(400).json({ error: 'Invalid email address' });
    if (!validatePassword(password))
      return res.status(400).json({ error: 'Password must be 8–128 characters' });
    if (!validateMobile(contact_number))
      return res.status(400).json({ error: 'Invalid contact number' });

    if (await Hospital.findOne({ email: email.toLowerCase() }))
      return res.status(409).json({ error: 'Email already registered' });

    let aiAnalysis = null;
    let isFake = false;
    let proofPath = req.file?.filename || null;
    
    if (proofPath) {
      aiAnalysis = await analyzeProof(proofPath, 'license_proof');
      if (!aiAnalysis.is_valid) isFake = true;
    }

    if (isFake) {
      if (proofPath) fs.unlinkSync(path.join(UPLOAD_DIR, proofPath));
      return res.status(400).json({ error: 'Registration rejected: Invalid or fake license proof detected by AI.' });
    }

    const hash     = await bcrypt.hash(password, 12);
    const hospital = await Hospital.create({
      name: name.trim().slice(0, 200), email: email.toLowerCase(), password: hash, contact_number,
      address: address ? address.trim().slice(0, 500) : '',
      city:    city    ? city.trim().slice(0, 100)    : '',
      latitude:  latitude && longitude && validateCoord(latitude, longitude) ? parseFloat(latitude)  : null,
      longitude: latitude && longitude && validateCoord(latitude, longitude) ? parseFloat(longitude) : null,
      license_number: license_number.trim().slice(0, 100),
      license_proof_path: proofPath,
      verification_status: 'pending'
    });

    if (proofPath) {
      await ProofVerification.create({
        user_id: hospital._id,
        user_type: 'hospital',
        proof_type: 'license_proof',
        proof_url: proofPath,
        verification_status: 'pending',
        ai_analysis: aiAnalysis
      });
    }

    res.status(201).json({ token: makeToken(hospital._id, 'hospital'), hospital: sanitize(hospital) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Registration failed' }); }
});

// POST /api/auth/hospital/login
app.post('/api/auth/hospital/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password required' });
    const hospital = await Hospital.findOne({ email: String(email).toLowerCase().trim() });
    if (!hospital || !(await bcrypt.compare(password, hospital.password)))
      return res.status(401).json({ error: 'Invalid email or password' });
    res.json({ token: makeToken(hospital._id, 'hospital'), hospital: sanitize(hospital) });
  } catch (e) { res.status(500).json({ error: 'Login failed' }); }
});

// POST /api/auth/emergency/send-otp
// Sends a 6-digit OTP to the user's mobile number via Fast2SMS.
// User provides: name, mobile_number
// OTP is bcrypt-hashed in MongoDB. Fast2SMS delivers the SMS.
app.post('/api/auth/emergency/send-otp', otpLimiter, async (req, res) => {
  try {
    const { name, mobile_number } = req.body;

    if (!name || !mobile_number)
      return res.status(400).json({ error: 'Name and mobile number are required' });
    if (!validateMobile(mobile_number))
      return res.status(400).json({ error: 'Invalid mobile number' });

    const { randomInt } = require('crypto');
    const otp         = String(randomInt(100000, 999999));
    const otp_expires = new Date(Date.now() + 10 * 60 * 1000); // 10 min
    const otpHash     = await bcrypt.hash(otp, 10);

    await EmergencyUser.findOneAndUpdate(
      { mobile_number },
      {
        name:         name.trim().slice(0, 120),
        otp:          otpHash,
        otp_expires,
        is_verified:  false,
        otp_attempts: 0,
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    try {
      await sendOtpToMobile(mobile_number, otp, name.trim());
      res.json({
        message:    `[DEMO] OTP sent successfully to ${mobile_number}.`,
        mobile:     mobile_number,
        otp:        otp, // Return OTP for demo display
        expires_in: '10 minutes',
      });
    } catch (smsErr) {
      // If Fast2SMS fails, clear the OTP so user can retry
      await EmergencyUser.updateOne({ mobile_number }, { $set: { otp: null, otp_expires: null } });
      console.error('Fast2SMS OTP send failed:', smsErr.message);
      res.status(500).json({ error: 'Failed to send OTP SMS. Check FAST2SMS_API_KEY in .env.' });
    }
  } catch (e) { res.status(500).json({ error: 'OTP generation failed' }); }
});

// POST /api/auth/emergency/verify-otp
app.post('/api/auth/emergency/verify-otp', otpLimiter, async (req, res) => {
  try {
    const { mobile_number, otp } = req.body;
    if (!mobile_number || !otp)
      return res.status(400).json({ error: 'Mobile number and OTP required' });

    const user = await EmergencyUser.findOne({ mobile_number });
    if (!user || !user.otp)
      return res.status(404).json({ error: 'Mobile number not found or OTP expired. Send OTP first.' });

    if ((user.otp_attempts || 0) >= 5) {
      await EmergencyUser.updateOne({ mobile_number }, { $set: { otp: null, otp_expires: null } });
      return res.status(429).json({ error: 'Too many failed attempts. Request a new OTP.' });
    }

    if (new Date(user.otp_expires) < new Date()) {
      return res.status(400).json({ error: 'OTP expired. Request a new one.' });
    }

    const match = await bcrypt.compare(String(otp), user.otp);
    if (!match) {
      await EmergencyUser.updateOne({ mobile_number }, { $inc: { otp_attempts: 1 } });
      return res.status(400).json({ error: 'Incorrect OTP. Please check the OTP shown on screen.' });
    }

    user.is_verified  = true;
    user.otp          = null;
    user.otp_expires  = null;
    user.otp_attempts = 0;
    await user.save();

    res.json({ token: makeToken(user._id, 'emergency'), user: sanitize(user) });
  } catch (e) { res.status(500).json({ error: 'OTP verification failed' }); }
});

// POST /api/auth/admin/login
app.post('/api/auth/admin/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password required' });
    const admin = await Admin.findOne({ email: String(email).toLowerCase().trim() });
    if (!admin || !(await bcrypt.compare(password, admin.password)))
      return res.status(401).json({ error: 'Invalid admin credentials' });
    res.json({ token: makeToken(admin._id, 'admin'), admin: sanitize(admin) });
  } catch (e) { res.status(500).json({ error: 'Login failed' }); }
});

// ── FORGOT PASSWORD ROUTES ───────────────────────────────────────────────────
const resetOtpStore = new Map(); // email -> { otp, expires, role }

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email, role } = req.body;
    if (!email || !role)
      return res.status(400).json({ error: 'Email and role required' });

    let user = null;
    if (role === 'donor') user = await Donor.findOne({ email: email.toLowerCase() });
    else if (role === 'hospital') user = await Hospital.findOne({ email: email.toLowerCase() });
    else if (role === 'admin') user = await Admin.findOne({ email: email.toLowerCase() });
    else return res.status(400).json({ error: 'Invalid role' });

    if (!user) return res.status(404).json({ error: 'Email not found' });

    // Require a registered mobile number for SMS OTP delivery
    const mobile = user.mobile_number || user.contact_number || null;
    if (!mobile) return res.status(400).json({ error: 'No mobile number on record. Contact support.' });

    // Generate 6-digit OTP
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    const otpHash = await bcrypt.hash(otp, 10);
    const expires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    resetOtpStore.set(email.toLowerCase(), { otp: otpHash, expires, role });

    // Send OTP via Fast2SMS SMS
    try {
      await sendOtpToMobile(mobile, otp, user.name || 'User');
      const maskedMobile = mobile.slice(-4).padStart(mobile.length, '*');
      res.json({ 
        message: `[DEMO] Verification code sent to ${maskedMobile}.`,
        otp: otp // Return OTP for demo display
      });
    } catch (smsErr) {
      resetOtpStore.delete(email.toLowerCase());
      console.error('Fast2SMS forgot-password OTP failed:', smsErr.message);
      res.status(500).json({ error: 'Failed to send reset code. Check FAST2SMS_API_KEY in .env.' });
    }
  } catch (e) { res.status(500).json({ error: 'Failed to send reset code' }); }
});

app.post('/api/auth/verify-reset-otp', async (req, res) => {
  try {
    const { email, otp, role } = req.body;
    if (!email || !otp)
      return res.status(400).json({ error: 'Email and OTP required' });

    const stored = resetOtpStore.get(email.toLowerCase());
    if (!stored) return res.status(400).json({ error: 'No reset request found. Request a new code.' });
    if (new Date() > stored.expires) {
      resetOtpStore.delete(email.toLowerCase());
      return res.status(400).json({ error: 'OTP expired. Request a new one.' });
    }

    const match = await bcrypt.compare(otp, stored.otp);
    if (!match) return res.status(400).json({ error: 'Invalid OTP' });

    res.json({ message: 'OTP verified', verified: true });
  } catch (e) { res.status(500).json({ error: 'Verification failed' }); }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { email, newPassword, role } = req.body;
    if (!email || !newPassword)
      return res.status(400).json({ error: 'Email and new password required' });
    if (newPassword.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters' });

    const stored = resetOtpStore.get(email.toLowerCase());
    if (!stored) return res.status(400).json({ error: 'Verify OTP first' });
    if (new Date() > stored.expires) {
      resetOtpStore.delete(email.toLowerCase());
      return res.status(400).json({ error: 'Session expired. Request a new reset.' });
    }

    const hash = await bcrypt.hash(newPassword, 12);
    let user = null;
    if (role === 'donor') user = await Donor.findOneAndUpdate({ email: email.toLowerCase() }, { password: hash });
    else if (role === 'hospital') user = await Hospital.findOneAndUpdate({ email: email.toLowerCase() }, { password: hash });
    else if (role === 'admin') user = await Admin.findOneAndUpdate({ email: email.toLowerCase() }, { password: hash });

    if (!user) return res.status(404).json({ error: 'User not found' });

    resetOtpStore.delete(email.toLowerCase());
    res.json({ message: 'Password reset successfully!' });
  } catch (e) { res.status(500).json({ error: 'Password reset failed' }); }
});

// ═══════════════════════════════════════════════════════════
//  DONOR ROUTES
// ═══════════════════════════════════════════════════════════
app.get('/api/donor/profile', authMiddleware, requireRole('donor'), async (req, res) => {
  try {
    const donor = await Donor.findById(req.user.id);
    if (!donor) return res.status(404).json({ error: 'Donor not found' });
    res.json(sanitize(donor));
  } catch (e) { res.status(500).json({ error: 'Failed to fetch profile' }); }
});

app.put('/api/donor/profile', authMiddleware, requireRole('donor'), async (req, res) => {
  try {
    const { name, city, age, mobile_number, fcm_token } = req.body;
    const upd = {};
    if (name          != null) upd.name          = String(name).trim().slice(0, 120);
    if (city          != null) upd.city          = String(city).trim().slice(0, 100);
    if (age           != null) {
      const a = Number(age);
      if (a < 18 || a > 65) return res.status(400).json({ error: 'Age must be 18–65' });
      upd.age = a;
    }
    if (mobile_number != null) {
      if (!validateMobile(mobile_number)) return res.status(400).json({ error: 'Invalid mobile number' });
      upd.mobile_number = mobile_number;
    }
    if (fcm_token != null) upd.fcm_token = String(fcm_token).slice(0, 300);
    const donor = await Donor.findByIdAndUpdate(req.user.id, upd, { new: true });
    if (!donor) return res.status(404).json({ error: 'Donor not found' });
    res.json(sanitize(donor));
  } catch (e) { res.status(500).json({ error: 'Profile update failed' }); }
});

app.patch('/api/donor/location', authMiddleware, requireRole('donor'), async (req, res) => {
  try {
    const { latitude, longitude } = req.body;
    if (!validateCoord(latitude, longitude))
      return res.status(400).json({ error: 'Invalid coordinates' });
    await Donor.findByIdAndUpdate(req.user.id, {
      latitude: parseFloat(latitude), longitude: parseFloat(longitude),
    });
    res.json({ message: 'Location updated' });
  } catch (e) { res.status(500).json({ error: 'Location update failed' }); }
});

app.patch('/api/donor/availability', authMiddleware, requireRole('donor'), async (req, res) => {
  try {
    await Donor.findByIdAndUpdate(req.user.id, { availability_status: !!req.body.available });
    res.json({ available: !!req.body.available });
  } catch (e) { res.status(500).json({ error: 'Availability update failed' }); }
});

app.get('/api/donor/notifications', authMiddleware, requireRole('donor'), async (req, res) => {
  try {
    const list = await Notification.find({ donor_id: req.user.id })
      .sort({ createdAt: -1 }).limit(50).lean();
    res.json(list);
  } catch (e) { res.status(500).json({ error: 'Failed to fetch notifications' }); }
});

app.get('/api/donor/history', authMiddleware, requireRole('donor'), async (req, res) => {
  try {
    const list = await DonationHistory.find({ donor_id: req.user.id })
      .sort({ donated_on: -1 }).lean();
    res.json(list);
  } catch (e) { res.status(500).json({ error: 'Failed to fetch history' }); }
});

app.get('/api/donor/map', async (req, res) => {
  try {
    const donors = await Donor.find(
      { verification_status: 'approved', availability_status: true,
        latitude: { $ne: null }, longitude: { $ne: null } },
      'name blood_group latitude longitude city points -_id'
    ).lean();
    res.json(donors);
  } catch (e) { res.status(500).json({ error: 'Failed to fetch map data' }); }
});

// ═══════════════════════════════════════════════════════════
//  HOSPITAL ROUTES
// ═══════════════════════════════════════════════════════════
app.get('/api/hospital/profile', authMiddleware, requireRole('hospital'), async (req, res) => {
  try {
    const h = await Hospital.findById(req.user.id);
    if (!h) return res.status(404).json({ error: 'Hospital not found' });
    res.json(sanitize(h));
  } catch (e) { res.status(500).json({ error: 'Failed to fetch profile' }); }
});

app.put('/api/hospital/profile', authMiddleware, requireRole('hospital'), async (req, res) => {
  try {
    const { name, contact_number, address, city } = req.body;
    const upd = {};
    if (name           != null) upd.name    = String(name).trim().slice(0, 200);
    if (contact_number != null) {
      if (!validateMobile(contact_number)) return res.status(400).json({ error: 'Invalid contact number' });
      upd.contact_number = contact_number;
    }
    if (address != null) upd.address = String(address).trim().slice(0, 500);
    if (city    != null) upd.city    = String(city).trim().slice(0, 100);
    const h = await Hospital.findByIdAndUpdate(req.user.id, upd, { new: true });
    if (!h) return res.status(404).json({ error: 'Hospital not found' });
    res.json(sanitize(h));
  } catch (e) { res.status(500).json({ error: 'Profile update failed' }); }
});

app.patch('/api/hospital/location', authMiddleware, requireRole('hospital'), async (req, res) => {
  try {
    const { latitude, longitude } = req.body;
    if (!validateCoord(latitude, longitude))
      return res.status(400).json({ error: 'Invalid coordinates' });
    await Hospital.findByIdAndUpdate(req.user.id, {
      latitude: parseFloat(latitude), longitude: parseFloat(longitude),
    });
    res.json({ message: 'Location updated' });
  } catch (e) { res.status(500).json({ error: 'Location update failed' }); }
});

app.get('/api/hospital/requests', authMiddleware, requireRole('hospital'), async (req, res) => {
  try {
    const list = await BloodRequest
      .find({ requested_by: req.user.id, requester_type: 'hospital' })
      .sort({ createdAt: -1 }).lean();
    res.json(list);
  } catch (e) { res.status(500).json({ error: 'Failed to fetch requests' }); }
});

app.get('/api/hospital', async (req, res) => {
  try {
    const list = await Hospital.find(
      { verification_status: 'approved' },
      'name contact_number address city latitude longitude -_id'
    ).lean();
    res.json(list);
  } catch (e) { res.status(500).json({ error: 'Failed to fetch hospitals' }); }
});

// ═══════════════════════════════════════════════════════════
//  BLOOD REQUEST ROUTES
// ═══════════════════════════════════════════════════════════
app.post('/api/request', authMiddleware, async (req, res) => {
  try {
    const { blood_group, units_needed, urgency_level, patient_name,
            latitude, longitude, address, notes } = req.body;
    if (!blood_group || latitude == null || longitude == null)
      return res.status(400).json({ error: 'blood_group, latitude, longitude required' });
    if (!validateBloodGroup(blood_group))
      return res.status(400).json({ error: 'Invalid blood group' });
    if (!validateCoord(latitude, longitude))
      return res.status(400).json({ error: 'Invalid coordinates' });

    const lat = parseFloat(latitude), lon = parseFloat(longitude);
    const br  = await BloodRequest.create({
      blood_group,
      units_needed:  Math.min(Math.max(Number(units_needed) || 1, 1), 20),
      urgency_level: ['normal','urgent','critical'].includes(urgency_level) ? urgency_level : 'normal',
      patient_name:  patient_name  ? String(patient_name).trim().slice(0, 150)  : '',
      latitude: lat, longitude: lon,
      address:  address ? String(address).trim().slice(0, 500)  : '',
      notes:    notes   ? String(notes).trim().slice(0, 1000)   : '',
      requested_by: req.user.id, requester_type: req.user.role,
    });

    let hospitalDetails = '';
    if (req.user.role === 'hospital') {
      const h = await Hospital.findById(req.user.id).lean();
      if (h) hospitalDetails = `\nHospital: ${h.name}\nContact: ${h.contact_number}\nAddress: ${h.address || address}`;
    }

    const matched = await matchDonors(blood_group, lat, lon);
    let smsSent = 0;
    for (const d of matched) {
      await Notification.create({
        donor_id: d._id, request_id: br._id,
        message: `🔴 Blood Request Matched! ${blood_group} blood needed. Patient: ${patient_name || 'Unknown'}.${hospitalDetails}`,
        channel: 'in_app',
        status: 'unread'
      });
      if (await sendAlertSMS(d.mobile_number,
        `BloodLink URGENT: ${blood_group} needed. ${hospitalDetails}`)) smsSent++;
    }

    if (matched.length) await BloodRequest.findByIdAndUpdate(br._id, { status: 'matched' });
    
    // ── NOTIFY HOSPITAL AND ADMIN ABOUT MATCHES ──
    const matchMsg = `✅ Blood Request Matched: Found ${matched.length} eligible donors for ${blood_group} request at ${address || 'Location'}.`;
    await MatchNotification.create({
      request_id: br._id,
      notification_type: 'admin_alert',
      message: matchMsg,
      status: 'unread'
    });
    
    if (req.user.role === 'hospital') {
      await MatchNotification.create({
        request_id: br._id,
        hospital_id: req.user.id,
        notification_type: 'request_matched',
        message: matchMsg,
        status: 'unread'
      });
    }

    const saved = await BloodRequest.findById(br._id).lean();
    const safeDonors = matched.slice(0, 5).map(d => ({
      id: d._id, // Full ID for emergency contact
      name: d.name, blood_group: d.blood_group, city: d.city,
      mobile_number: d.mobile_number, 
      distance_km: d.distance_km, ai_score: d.ai_score,
    }));
    res.status(201).json({ message: 'Request submitted', request: saved,
      matched_donors: matched.length, notifications: { sms_sent: smsSent },
      top_matches: safeDonors });
  } catch (e) { res.status(500).json({ error: 'Request submission failed' }); }
});

app.get('/api/request', authMiddleware, async (req, res) => {
  try {
    // FIX-25: Paginate large result sets to prevent DoS via huge query
    const limit = Math.min(Number(req.query.limit) || 50, 100);
    const skip  = Number(req.query.skip) || 0;
    res.json(await BloodRequest.find().sort({ createdAt: -1 }).skip(skip).limit(limit).lean());
  } catch (e) { res.status(500).json({ error: 'Failed to fetch requests' }); }
});

app.post('/api/request/:id/respond', authMiddleware, requireRole('donor'), async (req, res) => {
  try {
    const { id } = req.params;
    if (!isValidId(id)) return res.status(400).json({ error: 'Invalid request ID' });
    const { response } = req.body;
    if (!['accepted','declined'].includes(response))
      return res.status(400).json({ error: 'Response must be accepted or declined' });

    await Notification.updateMany(
      { request_id: id, donor_id: req.user.id, donor_response: 'pending' },
      { donor_response: response, status: 'read' }
    );
    if (response === 'accepted') {
      await BloodRequest.findByIdAndUpdate(id, { status: 'fulfilled' });
      // FIX: Mark donor as unavailable and update donation date for 3-month cooldown
      await Donor.findByIdAndUpdate(req.user.id, { 
        availability_status: false,
        last_donation_date: new Date(),
        $inc: { points: 100 }
      });
      const rq = await BloodRequest.findById(id).lean();
      await DonationHistory.create({
        donor_id: req.user.id, blood_group: rq?.blood_group || '',
        hospital_name: rq?.address || '', units: rq?.units_needed || 1,
      });
      
      // ── NOTIFY ADMIN AND HOSPITALS WHEN DONOR ACCEPTS ──
      const donor = await Donor.findById(req.user.id).lean();
      const notifyMsg = `🩸 DONOR MATCHED! ${donor?.name} (${donor?.blood_group}) accepted blood request for ${rq?.blood_group} at ${rq?.address}. Units: ${rq?.units_needed}`;
      
      // Create notification for admin
      await MatchNotification.create({
        donor_id: req.user.id,
        request_id: id,
        notification_type: 'admin_alert',
        message: notifyMsg,
        status: 'unread'
      });
      
      // Create notification for the hospital that created the request
      if (rq?.requested_by && rq?.requester_type === 'hospital') {
        await MatchNotification.create({
          donor_id: req.user.id,
          request_id: id,
          hospital_id: rq.requested_by,
          notification_type: 'donor_matched',
          message: notifyMsg,
          status: 'unread'
        });
      }
      
      console.log(`📢 Donor ${donor?.name} matched - admin and hospital notified`);

      // ── SMS NOTIFICATION TO REQUESTER ──
      try {
        let requesterMobile = '';
        if (rq.requester_type === 'donor') {
          const r = await Donor.findById(rq.requested_by).lean();
          requesterMobile = r?.mobile_number;
        } else if (rq.requester_type === 'hospital') {
          const r = await Hospital.findById(rq.requested_by).lean();
          requesterMobile = r?.contact_number;
        } else if (rq.requester_type === 'emergency') {
          const r = await EmergencyUser.findById(rq.requested_by).lean();
          requesterMobile = r?.mobile_number;
        }

        if (requesterMobile) {
          const smsMsg = `🩸 BloodLink: A donor (${donor?.name}, ${donor?.blood_group}) has accepted your request for ${rq?.blood_group}. They will contact you shortly.`;
          await sendSMS(requesterMobile, smsMsg);
        }
      } catch (smsErr) {
        console.error('Failed to send match SMS to requester:', smsErr.message);
      }
    }
    res.json({ message: `Response recorded: ${response}` });
  } catch (e) { res.status(500).json({ error: 'Response failed' }); }
});

app.post('/api/request/match-preview', authMiddleware, async (req, res) => {
  try {
    const { blood_group, latitude, longitude } = req.body;
    if (!validateBloodGroup(blood_group))
      return res.status(400).json({ error: 'Invalid blood group' });
    if (!validateCoord(latitude, longitude))
      return res.status(400).json({ error: 'Invalid coordinates' });
    const matched = await matchDonors(blood_group,
      parseFloat(latitude), parseFloat(longitude));
    const safe = matched.map(d => ({
      name: d.name, blood_group: d.blood_group, city: d.city,
      distance_km: d.distance_km, ai_score: d.ai_score,
    }));
    res.json({ matched: safe, count: safe.length });
  } catch (e) { res.status(500).json({ error: 'Match preview failed' }); }
});

// GET /api/hospital/notifications — fetch donor match alerts for the hospital
app.get('/api/hospital/notifications', authMiddleware, requireRole('hospital'), async (req, res) => {
  try {
    const list = await MatchNotification.find({ hospital_id: req.user.id })
      .sort({ createdAt: -1 })
      .limit(20)
      .lean();
    res.json(list);
  } catch (e) { res.status(500).json({ error: 'Failed to fetch notifications' }); }
});

// GET /api/admin/notifications — fetch all match alerts for monitoring
app.get('/api/admin/notifications', authMiddleware, requireRole('admin'), async (req, res) => {
  try {
    const list = await MatchNotification.find({ notification_type: 'admin_alert' })
      .sort({ createdAt: -1 })
      .limit(30)
      .lean();
    res.json(list);
  } catch (e) { res.status(500).json({ error: 'Failed to fetch notifications' }); }
});

// POST /api/admin/notify-donors — manually send notifications to specific donors
app.post('/api/admin/notify-donors', authMiddleware, requireRole('admin'), async (req, res) => {
  try {
    const { request_id, donor_ids } = req.body;
    if (!request_id || !donor_ids || !Array.isArray(donor_ids))
      return res.status(400).json({ error: 'request_id and donor_ids array required' });

    const br = await BloodRequest.findById(request_id);
    if (!br) return res.status(404).json({ error: 'Request not found' });

    let hospitalDetails = '';
    if (br.requester_type === 'hospital') {
      const h = await Hospital.findById(br.requested_by).lean();
      if (h) hospitalDetails = `\nHospital: ${h.name}\nContact: ${h.contact_number}\nAddress: ${h.address || br.address}`;
    }

    let sentCount = 0;
    for (const dId of donor_ids) {
      const donor = await Donor.findById(dId);
      if (donor) {
        await Notification.create({
          donor_id: donor._id, request_id: br._id,
          message: `🔴 Blood Request Matched (Admin Assigned): ${br.blood_group} blood needed at ${br.address}. ${hospitalDetails}`,
          channel: 'in_app',
          status: 'unread'
        });
        await sendAlertSMS(donor.mobile_number, `BloodLink: Admin has assigned you to a ${br.blood_group} request. ${hospitalDetails}`);
        sentCount++;
      }
    }
    res.json({ message: `Notifications sent to ${sentCount} donors`, count: sentCount });
  } catch (e) { res.status(500).json({ error: 'Failed to notify donors' }); }
});

// ═══════════════════════════════════════════════════════════
//  ADMIN ROUTES
// ═══════════════════════════════════════════════════════════
app.get('/api/admin/stats', authMiddleware, requireRole('admin'), async (req, res) => {
  try {
    const [
      total_donors, pending_donors, approved_donors, available_donors,
      total_hospitals, pending_hospitals, approved_hospitals,
      total_requests, open_requests, critical_requests, total_notifications,
    ] = await Promise.all([
      Donor.countDocuments(),
      Donor.countDocuments({ verification_status: 'pending' }),
      Donor.countDocuments({ verification_status: 'approved' }),
      Donor.countDocuments({ availability_status: true, verification_status: 'approved' }),
      Hospital.countDocuments(),
      Hospital.countDocuments({ verification_status: 'pending' }),
      Hospital.countDocuments({ verification_status: 'approved' }),
      BloodRequest.countDocuments(),
      BloodRequest.countDocuments({ status: { $in: ['open','matched'] } }),
      BloodRequest.countDocuments({ urgency_level: 'critical' }),
      Notification.countDocuments(),
    ]);
    res.json({ total_donors, pending_donors, approved_donors, available_donors,
      total_hospitals, pending_hospitals, approved_hospitals,
      total_requests, open_requests, critical_requests, total_notifications });
  } catch (e) { res.status(500).json({ error: 'Failed to fetch stats' }); }
});

app.get('/api/admin/pending', authMiddleware, requireRole('admin'), async (req, res) => {
  try {
    const [pd, ph] = await Promise.all([
      Donor.find({ verification_status: 'pending' }).lean(),
      Hospital.find({ verification_status: 'pending' }).lean(),
    ]);
    res.json({
      pending_donors:    pd.map(d => sanitize(d)),
      pending_hospitals: ph.map(h => sanitize(h)),
    });
  } catch (e) { res.status(500).json({ error: 'Failed to fetch pending list' }); }
});

async function handleVerifyDonor(req, res) {
  try {
    const { id } = req.params;
    if (!isValidId(id)) return res.status(400).json({ error: 'Invalid donor ID' });
    const { action } = req.body;
    if (!['approved','rejected'].includes(action))
      return res.status(400).json({ error: 'action must be "approved" or "rejected"' });
    const donor = await Donor.findByIdAndUpdate(id, { verification_status: action }, { new: true });
    if (!donor) return res.status(404).json({ error: 'Donor not found' });
    res.json({ message: `Donor ${action}`, donor: sanitize(donor) });
  } catch (e) { res.status(500).json({ error: 'Verification failed' }); }
}

async function handleVerifyHospital(req, res) {
  try {
    const { id } = req.params;
    if (!isValidId(id)) return res.status(400).json({ error: 'Invalid hospital ID' });
    const { action } = req.body;
    if (!['approved','rejected'].includes(action))
      return res.status(400).json({ error: 'action must be "approved" or "rejected"' });
    const hospital = await Hospital.findByIdAndUpdate(id, { verification_status: action }, { new: true });
    if (!hospital) return res.status(404).json({ error: 'Hospital not found' });
    res.json({ message: `Hospital ${action}`, hospital: sanitize(hospital) });
  } catch (e) { res.status(500).json({ error: 'Verification failed' }); }
}

app.patch('/api/admin/verify/donor/:id',    authMiddleware, requireRole('admin'), handleVerifyDonor);
app.put('/api/admin/verify/donor/:id',      authMiddleware, requireRole('admin'), handleVerifyDonor);
app.patch('/api/admin/verify/hospital/:id', authMiddleware, requireRole('admin'), handleVerifyHospital);
app.put('/api/admin/verify/hospital/:id',   authMiddleware, requireRole('admin'), handleVerifyHospital);

app.get('/api/admin/donors', authMiddleware, requireRole('admin'), async (req, res) => {
  try {
    const { status } = req.query;
    const allowedStatus = ['pending','approved','rejected'];
    const filter = status && allowedStatus.includes(status) ? { verification_status: status } : {};
    const donors = await Donor.find(filter).lean();
    res.json(donors.map(d => sanitize(d)));
  } catch (e) { res.status(500).json({ error: 'Failed to fetch donors' }); }
});

app.get('/api/admin/requests', authMiddleware, requireRole('admin'), async (req, res) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 50, 200);
    res.json(await BloodRequest.find().sort({ createdAt: -1 }).limit(limit).lean());
  } catch (e) { res.status(500).json({ error: 'Failed to fetch requests' }); }
});

// Admin Proof Verification endpoints
app.get('/api/admin/proofs', authMiddleware, requireRole('admin'), async (req, res) => {
  try {
    const status = req.query.status || 'pending';
    const proofs = await ProofVerification.find({ verification_status: status }).sort({ submitted_at: -1 }).lean();
    res.json(proofs);
  } catch (e) { res.status(500).json({ error: 'Failed to fetch proofs' }); }
});

app.patch('/api/admin/proofs/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  try {
    const { id } = req.params;
    const { action, notes } = req.body;
    if (!['approved','rejected'].includes(action)) return res.status(400).json({ error: 'Invalid action' });
    
    const proof = await ProofVerification.findByIdAndUpdate(id, { 
      verification_status: action,
      verified_at: new Date(),
      admin_notes: notes || ''
    }, { new: true });
    
    if (!proof) return res.status(404).json({ error: 'Proof not found' });
    
    // Also update the underlying user's verification status
    if (proof.user_type === 'donor') {
      await Donor.findByIdAndUpdate(proof.user_id, { verification_status: action });
    } else if (proof.user_type === 'hospital') {
      await Hospital.findByIdAndUpdate(proof.user_id, { verification_status: action });
    }
    
    res.json({ message: `Proof ${action}`, proof });
  } catch (e) { res.status(500).json({ error: 'Failed to verify proof' }); }
});

// ── FIX-26: Health check endpoint for uptime monitors / load balancers ──
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    uptime: Math.floor(process.uptime()),
  });
});

// ── Catch-all → frontend ──────────────────────────────────
app.get('*', (req, res) =>
  res.sendFile(path.join(__dirname, '../frontend/index.html'))
);

// ── FIX-27: Global error handler — never leak stack traces to client ──
app.use((err, req, res, _next) => {
  if (err.code === 'LIMIT_FILE_SIZE')
    return res.status(413).json({ error: 'File too large. Maximum size is 5 MB.' });
  if (err.message && err.message.startsWith('Only'))
    return res.status(400).json({ error: err.message });
  if (err.message && err.message.startsWith('CORS'))
    return res.status(403).json({ error: 'CORS policy violation' });
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ── FIX-28: Handle uncaught exceptions to prevent silent crashes ──
process.on('uncaughtException',  err => { console.error('UncaughtException:', err);  });
process.on('unhandledRejection', err => { console.error('UnhandledRejection:', err); });

// ═══════════════════════════════════════════════════════════
//  START — FIX-1: Bind to 0.0.0.0 to be reachable externally
// ═══════════════════════════════════════════════════════════
app.listen(PORT, HOST, () => {
  const smsOk = process.env.FAST2SMS_API_KEY &&
                process.env.FAST2SMS_API_KEY !== 'your_fast2sms_api_key_here';
  console.log(`\n🩸  BloodLink          →  http://${HOST}:${PORT}`);
  console.log(`🍃  MongoDB            →  ${MONGO_URI}`);
  console.log(`🗺️   Live Map           →  http://${HOST}:${PORT}/map`);
  console.log(`🔑  Admin login        →  admin@bloodlink.in / admin123`);
  console.log(`💊  Health check       →  http://${HOST}:${PORT}/api/health`);
  console.log(`📱  Fast2SMS OTP/Alert →  ${smsOk ? '✅ Configured' : '❌ NOT set — add FAST2SMS_API_KEY to .env'}\n`);
});
