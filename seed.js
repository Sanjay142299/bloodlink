// ═══════════════════════════════════════════════════════════
//  BloodLink — Database Seeder
//  Populates: 1 Admin, 10 Donors, 5 Hospitals, 3 Blood Requests
//  Run:  node seed.js
//  (Make sure your .env is configured with MONGO_URI first)
// ═══════════════════════════════════════════════════════════

'use strict';

const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');
require('dotenv').config();

const MONGO_URI = process.env.MONGO_URI;
if (!MONGO_URI) {
  console.error('❌ MONGO_URI not set in .env');
  process.exit(1);
}

// ── Schemas (must match server.js) ──────────────────────
const AdminSchema = new mongoose.Schema({
  username: String,
  email:    String,
  password: String,
}, { timestamps: true });

const DonorSchema = new mongoose.Schema({
  name:                String,
  email:               String,
  password:            String,
  blood_group:         String,
  mobile_number:       String,
  age:                 Number,
  city:                String,
  latitude:            Number,
  longitude:           Number,
  availability_status: { type: Boolean, default: true },
  last_donation_date:  { type: Date,    default: null },
  verification_status: { type: String,  default: 'approved' },
  points:              { type: Number,  default: 50 },
  login_attempts:      { type: Number,  default: 0 },
  locked_until:        { type: Date,    default: null },
}, { timestamps: true });

const HospitalSchema = new mongoose.Schema({
  name:                String,
  email:               String,
  password:            String,
  contact_number:      String,
  address:             String,
  city:                String,
  latitude:            Number,
  longitude:           Number,
  license_number:      String,
  verification_status: { type: String, default: 'approved' },
}, { timestamps: true });

const BloodRequestSchema = new mongoose.Schema({
  blood_group:    String,
  units_needed:   Number,
  urgency_level:  String,
  patient_name:   String,
  latitude:       Number,
  longitude:      Number,
  address:        String,
  status:         { type: String, default: 'open' },
  notes:          String,
  requester_type: String,
}, { timestamps: true });

const Admin        = mongoose.model('Admin',        AdminSchema);
const Donor        = mongoose.model('Donor',        DonorSchema);
const Hospital     = mongoose.model('Hospital',     HospitalSchema);
const BloodRequest = mongoose.model('BloodRequest', BloodRequestSchema);

// ── Sample Data ──────────────────────────────────────────

const DONORS = [
  { name: 'Arjun Kumar',   email: 'arjun@demo.com',   blood_group: 'O+',  mobile_number: '9876543210', age: 28, city: 'Chennai',   latitude: 13.0827, longitude: 80.2707, points: 150 },
  { name: 'Priya Sharma',  email: 'priya@demo.com',   blood_group: 'A+',  mobile_number: '9876543211', age: 25, city: 'Bengaluru',  latitude: 12.9716, longitude: 77.5946, points: 200 },
  { name: 'Ravi Menon',    email: 'ravi@demo.com',    blood_group: 'B+',  mobile_number: '9876543212', age: 32, city: 'Hyderabad',  latitude: 17.3850, longitude: 78.4867, points: 75  },
  { name: 'Sunita Nair',   email: 'sunita@demo.com',  blood_group: 'AB+', mobile_number: '9876543213', age: 29, city: 'Kochi',      latitude: 9.9312,  longitude: 76.2673, points: 120 },
  { name: 'Deepak Singh',  email: 'deepak@demo.com',  blood_group: 'O-',  mobile_number: '9876543214', age: 35, city: 'Mumbai',     latitude: 19.0760, longitude: 72.8777, points: 300 },
  { name: 'Anitha Raj',    email: 'anitha@demo.com',  blood_group: 'A-',  mobile_number: '9876543215', age: 27, city: 'Coimbatore', latitude: 11.0168, longitude: 76.9558, points: 90  },
  { name: 'Vikram Patel',  email: 'vikram@demo.com',  blood_group: 'B-',  mobile_number: '9876543216', age: 30, city: 'Ahmedabad',  latitude: 23.0225, longitude: 72.5714, points: 60  },
  { name: 'Kavya Reddy',   email: 'kavya@demo.com',   blood_group: 'AB-', mobile_number: '9876543217', age: 24, city: 'Vijayawada', latitude: 16.5062, longitude: 80.6480, points: 140 },
  { name: 'Suresh Iyer',   email: 'suresh@demo.com',  blood_group: 'O+',  mobile_number: '9876543218', age: 40, city: 'Madurai',    latitude: 9.9252,  longitude: 78.1198, points: 220 },
  { name: 'Meena Pillai',  email: 'meena@demo.com',   blood_group: 'A+',  mobile_number: '9876543219', age: 22, city: 'Trichy',     latitude: 10.7905, longitude: 78.7047, points: 50  },
];

const HOSPITALS = [
  { name: 'Apollo Hospitals Chennai',    email: 'apollo.chennai@demo.com',    contact_number: '04428296000', address: '21 Greams Lane, Off Greams Road', city: 'Chennai',   latitude: 13.0569, longitude: 80.2425, license_number: 'TN-MED-001' },
  { name: 'Manipal Hospital Bengaluru',  email: 'manipal.blr@demo.com',       contact_number: '08025024444', address: '98 HAL Airport Road, Kodihalli',  city: 'Bengaluru', latitude: 12.9592, longitude: 77.6471, license_number: 'KA-MED-102' },
  { name: 'Care Hospitals Hyderabad',    email: 'care.hyd@demo.com',          contact_number: '04067898000', address: 'Road No 1, Banjara Hills',        city: 'Hyderabad', latitude: 17.4138, longitude: 78.4489, license_number: 'TS-MED-055' },
  { name: 'Amrita Hospital Kochi',       email: 'amrita.kochi@demo.com',      contact_number: '04842851234', address: 'AIMS Ponekkara PO, Edappally',    city: 'Kochi',     latitude: 10.0303, longitude: 76.3095, license_number: 'KL-MED-033' },
  { name: 'PSG Hospitals Coimbatore',    email: 'psg.cbe@demo.com',           contact_number: '04222570170', address: 'Peelamedu, Avinashi Road',        city: 'Coimbatore',latitude: 11.0272, longitude: 77.0144, license_number: 'TN-MED-089' },
];

const BLOOD_REQUESTS = [
  { blood_group: 'O+',  units_needed: 2, urgency_level: 'critical', patient_name: 'Ramesh Kumar',   latitude: 13.0827, longitude: 80.2707, address: 'Apollo Chennai',      notes: 'Post-surgery emergency',   requester_type: 'hospital', status: 'open'      },
  { blood_group: 'A-',  units_needed: 1, urgency_level: 'urgent',   patient_name: 'Leela Devi',     latitude: 12.9716, longitude: 77.5946, address: 'Manipal Bengaluru',   notes: 'Accident case',            requester_type: 'hospital', status: 'open'      },
  { blood_group: 'B+',  units_needed: 3, urgency_level: 'normal',   patient_name: 'Gopal Rao',      latitude: 17.3850, longitude: 78.4867, address: 'Care Hospitals Hyd',  notes: 'Elective surgery planned', requester_type: 'hospital', status: 'matched'   },
];

// ── Main Seeder ──────────────────────────────────────────
async function seed() {
  await mongoose.connect(MONGO_URI, {
    serverSelectionTimeoutMS: 10000,
  });
  console.log('✅ Connected to MongoDB\n');

  // Clear existing seed data
  await Admin.deleteMany({});
  await Donor.deleteMany({});
  await Hospital.deleteMany({});
  await BloodRequest.deleteMany({});
  console.log('🗑️  Cleared existing data\n');

  // Seed Admin
  const adminHash = await bcrypt.hash('admin123', 12);
  await Admin.create({
    username: 'admin',
    email: 'admin@bloodlink.in',
    password: adminHash,
  });
  console.log('👤 Admin created  →  admin@bloodlink.in / admin123');

  // Seed Donors
  const donorHash = await bcrypt.hash('donor123', 12);
  for (const d of DONORS) {
    await Donor.create({ ...d, password: donorHash, verification_status: 'approved', availability_status: true });
  }
  console.log(`🩸 ${DONORS.length} donors created  →  password: donor123`);

  // Seed Hospitals
  const hospHash = await bcrypt.hash('hospital123', 12);
  for (const h of HOSPITALS) {
    await Hospital.create({ ...h, password: hospHash, verification_status: 'approved' });
  }
  console.log(`🏥 ${HOSPITALS.length} hospitals created  →  password: hospital123`);

  // Seed Blood Requests
  for (const r of BLOOD_REQUESTS) {
    await BloodRequest.create(r);
  }
  console.log(`📋 ${BLOOD_REQUESTS.length} blood requests created\n`);

  console.log('═══════════════════════════════════════════════════');
  console.log('✅ SEED COMPLETE — Demo Credentials:');
  console.log('  Admin    →  admin@bloodlink.in       / admin123');
  console.log('  Donors   →  arjun@demo.com, priya@demo.com ...  / donor123');
  console.log('  Hospitals→  apollo.chennai@demo.com ...         / hospital123');
  console.log('═══════════════════════════════════════════════════\n');

  await mongoose.disconnect();
  process.exit(0);
}

seed().catch(err => {
  console.error('❌ Seed failed:', err.message);
  process.exit(1);
});
