require("dotenv").config();

const argon2 = require("argon2");
const mongoose = require("mongoose");
const { Teacher } = require("./models");

async function seedAdmin() {
  const {
    MONGODB_URI,
    ADMIN_NATIONAL_ID,
    ADMIN_FIRST_NAME,
    ADMIN_LAST_NAME,
    ADMIN_PHONE,
    ADMIN_PASSWORD,
  } = process.env;

  if (!MONGODB_URI || !ADMIN_NATIONAL_ID || !ADMIN_PASSWORD) {
    throw new Error("Set the MongoDB URI, admin national ID, and one-time admin password in .env");
  }
  if (/^REPLACE_/i.test(ADMIN_PASSWORD) || ADMIN_PASSWORD.length < 16) {
    throw new Error("Set a unique admin password with at least 16 characters");
  }
  if (!/^\d{10}$/.test(ADMIN_NATIONAL_ID) || /^0+$/.test(ADMIN_NATIONAL_ID)) {
    throw new Error("Admin national ID must be a real 10-digit value, not the sample placeholder");
  }
  if (!ADMIN_PHONE || /^0+$/.test(ADMIN_PHONE.replace(/\D/g, ""))) {
    throw new Error("Set the admin phone number; the sample placeholder is not accepted");
  }

  await mongoose.connect(MONGODB_URI, { serverSelectionTimeoutMS: 10_000 });
  try {
    if (await Teacher.exists({ role: "admin" })) {
      throw new Error("An admin already exists; the initial admin seed can run only once");
    }
    await Teacher.create({
      firstName: ADMIN_FIRST_NAME || "مدیر",
      lastName: ADMIN_LAST_NAME || "مدرسه",
      nationalId: ADMIN_NATIONAL_ID,
      phone: ADMIN_PHONE,
      passwordHash: await argon2.hash(ADMIN_PASSWORD, {
        type: argon2.argon2id,
        memoryCost: 19_456,
        timeCost: 2,
        parallelism: 1,
      }),
      role: "admin",
      active: true,
      assignments: [],
    });
    console.log("Created the initial admin. Remove ADMIN_PASSWORD from .env now.");
  } finally {
    await mongoose.disconnect();
  }
}

seedAdmin().catch((error) => {
  console.error("Admin setup failed:", error.message);
  mongoose.disconnect().finally(() => process.exit(1));
});
