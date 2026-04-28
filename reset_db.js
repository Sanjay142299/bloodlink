const mongoose = require('mongoose');
require('dotenv').config();

const MONGO_URI = process.env.MONGO_URI;

mongoose.connect(MONGO_URI)
  .then(async () => {
    console.log('✅ Connected to MongoDB');
    
    const collections = [
      'donors',
      'hospitals',
      'bloodrequests',
      'notifications',
      'matchnotifications',
      'donationhistories',
      'proofverifications',
      'emergencyusers'
    ];

    const db = mongoose.connection.db;

    for (const name of collections) {
      try {
        const result = await db.collection(name).deleteMany({});
        console.log(`🗑️  Cleared ${name}: ${result.deletedCount} records deleted`);
      } catch (e) {
        console.log(`⚠️  Collection ${name} might not exist, skipping...`);
      }
    }

    console.log('✨ Database reset complete');
    process.exit(0);
  })
  .catch(err => {
    console.error('❌ Connection failed:', err);
    process.exit(1);
  });
