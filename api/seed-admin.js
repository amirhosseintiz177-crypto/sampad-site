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
  if (/^REPLACE_/i.test(ADMIN_PASSWORD) || ADMIN_PASSWORD.length < 6) {
    throw new Error("Admin password must contain at least 6 characters");
  }
  if (!/^\d{10}$/.test(ADMIN_NATIONAL_ID) || /^0+$/.test(ADMIN_NATIONAL_ID)) {
    throw new Error("Admin national ID must be a real 10-digit value, not the sample placeholder");
  }
  await mongoose.connect(MONGODB_URI, { serverSelectionTimeoutMS: 10_000 });
  try {
    const adminCount = await Teacher.countDocuments({ role: "admin" });
    if (adminCount > 1) throw new Error("Multiple admins exist; refusing an ambiguous password reset");
    const admin = await Teacher.findOne({ role: "admin" }).select("+passwordHash");
    if (admin && admin.nationalId !== ADMIN_NATIONAL_ID) {
      throw new Error("ADMIN_NATIONAL_ID does not match the existing admin; no account was changed");
    }
    const passwordHash = await argon2.hash(ADMIN_PASSWORD, {
      type: argon2.argon2id,
      memoryCost: 19_456,
      timeCost: 2,
      parallelism: 1,
    });
    if (admin) {
      admin.passwordHash = passwordHash;
      admin.tokenVersion = Number(admin.tokenVersion || 0) + 1;
      await admin.save();
      console.log("Updated the matching admin password and invalidated existing sessions. Remove ADMIN_PASSWORD now.");
    } else {
      if (!ADMIN_PHONE || /^0+$/.test(ADMIN_PHONE.replace(/\D/g, ""))) {
        throw new Error("Set the admin phone number; the sample placeholder is not accepted");
      }
      await Teacher.create({
        firstName: ADMIN_FIRST_NAME || "مدیر",
        lastName: ADMIN_LAST_NAME || "مدرسه",
        nationalId: ADMIN_NATIONAL_ID,
        phone: ADMIN_PHONE,
        passwordHash,
        role: "admin",
        active: true,
        assignments: [],
      });
      console.log("Created the initial admin. Site admin sign-in name is sampad; remove ADMIN_PASSWORD now.");
    }
  } finally {
    await mongoose.disconnect();
  }
}

seedAdmin().catch((error) => {
  console.error("Admin setup failed:", error.message);
  mongoose.disconnect().finally(() => process.exit(1));
});
