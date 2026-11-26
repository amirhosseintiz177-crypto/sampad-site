require("dotenv").config();
require("express-async-errors");

const express = require("express");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const { rateLimit } = require("express-rate-limit");
const argon2 = require("argon2");
const mongoose = require("mongoose");
const crypto = require("node:crypto");
const path = require("node:path");
const { z } = require("zod");

const {
  Teacher,
  Student,
  Report,
  ScoreAudit,
  AdminAudit,
  SyncChange,
  Counter,
  Config,
} = require("./models");

const app = express();
const APP_VERSION = (() => {
  try {
    return require("../package.json").version;
  } catch {
    return "unknown";
  }
})();
const SESSION_COOKIE = "sampad_session";
const SESSION_MS = 8 * 60 * 60 * 1000;
const DESKTOP_MANAGER_CONNECT_PATH = "/api/manager-link/7d8f4c91b2e648a6";
const IS_RENDER = process.env.RENDER === "true" || !!process.env.RENDER_EXTERNAL_URL;
function parseHttpsOrigin(value) {
  try {
    const url = new URL(String(value || ""));
    if (
      url.protocol !== "https:" ||
      !url.hostname ||
      url.username ||
      url.password ||
      url.pathname !== "/" ||
      url.search ||
      url.hash
    ) return null;
    return url.origin;
  } catch {
    return null;
  }
}
// PUBLIC_ORIGIN is the browser-visible HTTPS URL. Render's 0.0.0.0 value is
// only a bind host; use Render's generated public URL if the app URL is unset
// or was mistakenly set to a non-URL bind address.
function getPublicOrigin() {
  return parseHttpsOrigin(process.env.PUBLIC_ORIGIN) ||
    (IS_RENDER ? parseHttpsOrigin(process.env.RENDER_EXTERNAL_URL) : null);
}
const PUBLIC_ORIGIN = getPublicOrigin();
const TRUST_PROXY = process.env.TRUST_PROXY || "1";
const DEFAULT_PORT = Number(process.env.PORT || (IS_RENDER ? 10000 : 8080));
const DEFAULT_HOST = IS_RENDER ? "0.0.0.0" : (process.env.HOST || "127.0.0.1");
const ARGON_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
};

async function ensureInitialAdmin() {
  if (String(process.env.ADMIN_AUTO_PROVISION || "").toLowerCase() !== "true") return;

  const nationalId = String(process.env.ADMIN_NATIONAL_ID || "").trim();
  const phone = String(process.env.ADMIN_PHONE || "").trim();
  const password = String(process.env.ADMIN_PASSWORD || "");
  if (!/^\d{10}$/.test(nationalId) || /^0+$/.test(nationalId)) {
    throw new Error("ADMIN_AUTO_PROVISION requires a real 10-digit ADMIN_NATIONAL_ID");
  }
  if (!phone || /^0+$/.test(phone.replace(/\D/g, ""))) {
    throw new Error("ADMIN_AUTO_PROVISION requires ADMIN_PHONE");
  }
  if (/^REPLACE_/i.test(password) || password.length < 6) {
    throw new Error("ADMIN_AUTO_PROVISION requires ADMIN_PASSWORD of at least 6 characters");
  }

  const adminCount = await Teacher.countDocuments({ role: "admin" });
  if (adminCount > 1) throw new Error("Multiple admin accounts exist; automatic provisioning stopped");
  const admin = await Teacher.findOne({ role: "admin" });
  if (admin) {
    if (admin.nationalId !== nationalId) {
      throw new Error("ADMIN_NATIONAL_ID does not match the existing admin; automatic provisioning made no changes");
    }
    if (!admin.active) {
      admin.active = true;
      admin.tokenVersion = Number(admin.tokenVersion || 0) + 1;
      await admin.save();
      console.log("Activated the matching initial admin account.");
    }
    return;
  }

  const passwordHash = await argon2.hash(password, ARGON_OPTIONS);
  await Teacher.create({
    firstName: process.env.ADMIN_FIRST_NAME || "مدیر",
    lastName: process.env.ADMIN_LAST_NAME || "مدرسه",
    nationalId,
    phone,
    passwordHash,
    role: "admin",
    active: true,
    assignments: [],
  });
  console.log("Created the initial admin from Render environment settings.");
}

const required = ["MONGODB_URI", "JWT_SECRET"];
for (const key of required) {
  if (!process.env[key] || String(process.env[key]).startsWith("REPLACE_")) {
    throw new Error(`${key} is not configured`);
  }
}
if (Buffer.byteLength(String(process.env.JWT_SECRET)) < 48) {
  throw new Error("JWT_SECRET must contain at least 48 bytes");
}
if (process.env.NODE_ENV === "production") {
  if (!PUBLIC_ORIGIN) {
    throw new Error("Set PUBLIC_ORIGIN to the public HTTPS site URL; on Render, RENDER_EXTERNAL_URL is used as a secure fallback.");
  }
  if (process.env.COOKIE_SECURE === "false") {
    throw new Error("COOKIE_SECURE cannot be false in production; secure cookies are required.");
  }
  if (!Number.isInteger(Number(TRUST_PROXY)) || Number(TRUST_PROXY) < 1) {
    throw new Error("TRUST_PROXY must match the number of trusted reverse proxies");
  }
}

app.disable("x-powered-by");
app.set("trust proxy", Number(TRUST_PROXY));
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'none'"],
      },
    },
    crossOriginEmbedderPolicy: false,
    referrerPolicy: { policy: "no-referrer" },
  }),
);

app.use(express.json({ limit: "20mb", strict: true }));
app.use(cookieParser());

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 8,
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "تلاش‌های ورود بیش از حد بود؛ کمی بعد دوباره تلاش کن." },
});
const enrollmentLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "درخواست‌های ثبت‌نام زیاد شده؛ کمی بعد دوباره تلاش کن." },
});
const managerConnectLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 8,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "تلاش‌های اتصال مدیر بیش از حد بود؛ کمی بعد دوباره تلاش کنید." },
});
const writeLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 180,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "تعداد درخواست‌های نوشتن زیاد است؛ کمی بعد دوباره تلاش کن." },
});

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

const normalizeDigits = (value) =>
  String(value ?? "")
    .replace(/[۰-۹]/g, (d) => String("۰۱۲۳۴۵۶۷۸۹".indexOf(d)))
    .replace(/[٠-٩]/g, (d) => String("٠١٢٣٤٥٦٧٨٩".indexOf(d)));

const cleanText = (value, max = 160) =>
  String(value ?? "")
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .trim()
    .slice(0, max);

const normalizeSubjectKey = (value) =>
  normalizeDigits(String(value ?? "").trim())
    .toLocaleLowerCase("fa-IR")
    .replace(/[آأإ]/g, "ا")
    .replace(/ي/g, "ی")
    .replace(/ك/g, "ک")
    .replace(/[ۀة]/g, "ه")
    .replace(/[\u200c\s_\-.()]/g, "");

const reportKeyOf = (value) => normalizeSubjectKey(value || "کارنامه") || "کارنامه";
const identityKeyOf = (nationalId, year, reportType) =>
  `${nationalId}|${String(year || "").trim()}|${reportKeyOf(reportType)}`;

const escapeRegex = (value) => String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const safeJson = (value) => {
  try {
    return JSON.stringify(value);
  } catch {
    return "";
  }
};
const isPlainObject = (value) =>
  !!value && typeof value === "object" && !Array.isArray(value);

const stableObject = (value) => {
  if (Array.isArray(value)) return value.map(stableObject);
  if (!isPlainObject(value)) return value;
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((key) => [key, stableObject(value[key])]),
  );
};
const sameData = (left, right) => safeJson(stableObject(left)) === safeJson(stableObject(right));

const stripSyncMetadata = (record) => {
  if (!isPlainObject(record)) return {};
  const clean = { ...record };
  for (const key of [
    "siteRevision",
    "siteSyncedHash",
    "siteSyncedAt",
    "serverRevision",
    "revision",
    "syncBase",
    "deleted",
    "deletedAt",
    "deletedBy",
  ]) {
    delete clean[key];
  }
  return clean;
};

const comparableContent = (record) => {
  const clean = stripSyncMetadata(record);
  delete clean.revision;
  delete clean.serverUpdatedAt;
  return clean;
};

const toDate = (value, fallback = new Date()) => {
  const time = Date.parse(String(value || ""));
  return Number.isFinite(time) ? new Date(time) : fallback;
};

const iso = (value) => (value ? new Date(value).toISOString() : null);

function serializeStudent(doc) {
  const data = stripSyncMetadata(doc.data);
  return {
    ...data,
    nationalId: doc.nationalId,
    classId: doc.classId || data.classId || "",
    firstName: doc.firstName || data.firstName || "",
    lastName: doc.lastName || data.lastName || "",
    revision: doc.revision,
    serverRevision: doc.revision,
    updatedAt: iso(doc.updatedAt),
    serverUpdatedAt: iso(doc.serverUpdatedAt),
  };
}

function serializeReport(doc) {
  const data = stripSyncMetadata(doc.data);
  return {
    ...data,
    id: doc.id,
    nationalId: doc.nationalId,
    classId: doc.classId,
    academicYear: doc.academicYear,
    reportType: doc.reportType,
    revision: doc.revision,
    serverRevision: doc.revision,
    updatedAt: iso(doc.updatedAt),
    serverUpdatedAt: iso(doc.serverUpdatedAt),
  };
}

function publicTeacher(user) {
  return {
    id: String(user._id),
    firstName: user.firstName,
    lastName: user.lastName,
    nationalId: user.nationalId,
    phone: user.phone,
    role: user.role,
    active: user.active,
    lastSeenAt: user.lastSeenAt,
    lastLoginAt: user.lastLoginAt,
    loginCount: user.loginCount || 0,
    assignments: user.assignments,
    createdAt: user.createdAt,
  };
}

function sign(payload) {
  const head = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const data = `${head}.${body}`;
  const sig = crypto.createHmac("sha256", String(process.env.JWT_SECRET)).update(data).digest("base64url");
  return `${data}.${sig}`;
}

function readToken(token) {
  try {
    const [head, body, signature] = String(token || "").split(".");
    if (!head || !body || !signature) return null;
    const expected = crypto
      .createHmac("sha256", String(process.env.JWT_SECRET))
      .update(`${head}.${body}`)
      .digest();
    const actual = Buffer.from(signature, "base64url");
    if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return null;
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    return payload.exp > Date.now() / 1000 ? payload : null;
  } catch {
    return null;
  }
}

function setSessionCookie(res, token) {
  const secure =
    process.env.COOKIE_SECURE === "false"
      ? false
      : process.env.COOKIE_SECURE === "true" || process.env.NODE_ENV === "production";
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    secure,
    sameSite: "strict",
    path: "/",
    maxAge: SESSION_MS,
  });
}

function clearSessionCookie(res) {
  const secure =
    process.env.COOKIE_SECURE === "false"
      ? false
      : process.env.COOKIE_SECURE === "true" || process.env.NODE_ENV === "production";
  res.clearCookie(SESSION_COOKIE, {
    httpOnly: true,
    secure,
    sameSite: "strict",
    path: "/",
  });
}

function sessionToken(user) {
  const now = Date.now() / 1000;
  return sign({
    sub: String(user._id),
    role: user.role,
    ver: Number(user.tokenVersion || 0),
    iat: now,
    exp: now + SESSION_MS / 1000,
  });
}

async function auth(req, res, next) {
  const token = req.cookies?.[SESSION_COOKIE] || req.get("authorization")?.replace(/^Bearer\s+/i, "");
  const payload = readToken(token);
  if (!payload) return res.status(401).json({ error: "نشست معتبر نیست؛ دوباره وارد شوید." });
  const user = await Teacher.findById(payload.sub);
  if (!user || !user.active) return res.status(401).json({ error: "حساب غیرفعال یا حذف شده است." });
  if (Number(payload.ver || 0) !== Number(user.tokenVersion || 0)) {
    return res.status(401).json({ error: "نشست منقضی شده است؛ دوباره وارد شوید." });
  }
  req.user = user;
  next();
}

const adminOnly = (req, res, next) =>
  req.user?.role === "admin" ? next() : res.status(403).json({ error: "دسترسی مدیر لازم است." });

function sameOrigin(req, res, next) {
  const allowedOrigin = getPublicOrigin();
  const origin = req.get("origin");
  if (allowedOrigin && origin && origin !== "null") {
    if (origin !== allowedOrigin) return res.status(403).json({ error: "مبدأ درخواست مجاز نیست." });
  }
  next();
}

function enforceHttps(req, res, next) {
  const active =
    process.env.FORCE_HTTPS === "true" ||
    (process.env.NODE_ENV === "production" && process.env.COOKIE_SECURE !== "false");
  if (!active || req.secure) return next();
  if (req.path.startsWith("/api/")) return res.status(403).json({ error: "اتصال HTTPS الزامی است." });
  const target = getPublicOrigin() || `https://${req.hostname}`;
  return res.redirect(308, `${target}${req.originalUrl}`);
}

app.use(enforceHttps);
app.use("/api", sameOrigin);

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, service: "sampad-portal", version: APP_VERSION, time: new Date().toISOString() });
});

// ---------------------------------------------------------------------------
// Public bootstrap / registration
// ---------------------------------------------------------------------------

const assignmentInputSchema = z.object({
  classId: z.string().trim().min(1).max(120),
  subjectId: z.string().trim().min(1).max(120),
  subjectName: z.string().trim().min(1).max(160),
});

const registerSchema = z.object({
  firstName: z.string().trim().min(2).max(80),
  lastName: z.string().trim().min(2).max(80),
  nationalId: z.string().trim().regex(/^\d{10}$/),
  phone: z.string().trim().min(8).max(24),
  password: z.string().min(6).max(128),
  securityCode: z.string().trim().regex(/^\d{6}$/),
  assignments: z.array(assignmentInputSchema).min(1).max(100),
});

const profileSchema = z
  .object({
    firstName: z.string().trim().min(2).max(80),
    lastName: z.string().trim().min(2).max(80),
    phone: z.string().trim().min(8).max(24),
  })
  .partial();

const passwordSchema = z.object({
  currentPassword: z.string().min(1).max(128),
  newPassword: z.string().min(6).max(128),
});

async function getBootstrapConfig() {
  return Config.findOne({ key: "public-bootstrap" }).lean();
}

async function verifySecurityCode(input) {
  const code = normalizeDigits(input);
  if (!/^\d{6}$/.test(code)) return false;
  const cfg = await getBootstrapConfig();
  if (!cfg?.value?.securityCodeHash) return false;
  return argon2.verify(cfg.value.securityCodeHash, code).catch(() => false);
}

app.get("/api/bootstrap", enrollmentLimiter, async (_req, res) => {
  const cfg = await getBootstrapConfig();
  res.json({
    configured: !!cfg?.value?.securityCodeHash,
    updatedAt: cfg?.updatedAt || null,
  });
});

app.post("/api/bootstrap/verify", enrollmentLimiter, async (req, res) => {
  if (!(await verifySecurityCode(req.body?.securityCode))) {
    return res.status(403).json({ error: "کد امنیتی سایت نادرست است." });
  }
  const cfg = await getBootstrapConfig();
  res.json({
    classes: cfg?.value?.classes || [],
    subjects: cfg?.value?.subjects || [],
  });
});

app.post("/api/register", enrollmentLimiter, async (req, res) => {
  const body = {
    ...req.body,
    nationalId: normalizeDigits(req.body?.nationalId),
    securityCode: normalizeDigits(req.body?.securityCode),
  };
  const parsed = registerSchema.safeParse(body);
  if (!parsed.success) {
    return res.status(400).json({ error: "اطلاعات ثبت‌نام کامل یا معتبر نیست." });
  }
  if (!(await verifySecurityCode(parsed.data.securityCode))) {
    return res.status(403).json({ error: "کد امنیتی سایت نادرست است." });
  }
  const cfg = await getBootstrapConfig();
  const classes = cfg?.value?.classes || [];
  const subjects = cfg?.value?.subjects || [];
  const validAssignments = [];
  const seen = new Set();
  for (const assignment of parsed.data.assignments) {
    const klass = classes.find((item) => item.id === assignment.classId);
    const subject = subjects.find(
      (item) =>
        item.id === assignment.subjectId &&
        (!item.grade || Number(item.grade) === Number(klass?.grade)) &&
        (!item.field || item.field === klass?.field),
    );
    if (!klass || !subject || subject.name !== assignment.subjectName) continue;
    const key = `${klass.id}|${subject.id}`;
    if (seen.has(key)) continue;
    seen.add(key);
    validAssignments.push({
      classId: klass.id,
      subjectId: subject.id,
      subjectName: subject.name,
      grade: String(klass.grade || subject.grade || ""),
      field: String(klass.field || subject.field || ""),
    });
  }
  if (!validAssignments.length) {
    return res.status(400).json({ error: "هیچ ترکیب معتبر کلاس و درسی انتخاب نشده است." });
  }
  try {
    const user = await Teacher.create({
      firstName: parsed.data.firstName,
      lastName: parsed.data.lastName,
      nationalId: parsed.data.nationalId,
      phone: parsed.data.phone,
      passwordHash: await argon2.hash(parsed.data.password, ARGON_OPTIONS),
      role: "teacher",
      active: true,
      lastLoginAt: new Date(),
      lastSeenAt: new Date(),
      loginCount: 1,
      assignments: validAssignments,
    });
    setSessionCookie(res, sessionToken(user));
    await AdminAudit.create({
      action: "teacher_registered",
      targetType: "teacher",
      targetId: String(user._id),
      summary: `${user.firstName} ${user.lastName} ثبت‌نام کرد.`,
      result: "saved",
      actorId: user._id,
      actorName: `${user.firstName} ${user.lastName}`,
    });
    res.status(201).json({ user: publicTeacher(user) });
  } catch (error) {
    if (error?.code === 11000) return res.status(409).json({ error: "این کد ملی قبلاً ثبت شده است." });
    throw error;
  }
});

function matchesAdminEnvironmentPassword(candidate) {
  const expected = String(process.env.ADMIN_PASSWORD || "");
  if (expected.length < 6 || String(candidate || "").length > 128) return false;
  const receivedDigest = crypto.createHash("sha256").update(String(candidate || ""), "utf8").digest();
  const expectedDigest = crypto.createHash("sha256").update(expected, "utf8").digest();
  return crypto.timingSafeEqual(receivedDigest, expectedDigest);
}

async function performEnvironmentAdminLogin(req, res) {
  if (!process.env.ADMIN_PASSWORD || String(process.env.ADMIN_PASSWORD).length < 6) {
    return res.status(503).json({ error: "رمز اتصال مدیر در تنظیمات سرور تعریف نشده است." });
  }
  if (!matchesAdminEnvironmentPassword(req.body?.password)) {
    return res.status(401).json({ error: "رمز واردشده با مقدار ADMIN_PASSWORD سرور همخوان نیست." });
  }
  const user = await Teacher.findOne({ role: "admin", active: true }).select("+passwordHash");
  if (!user) return res.status(503).json({ error: "حساب مدیر در پایگاه داده آماده نیست." });
  user.lastSeenAt = new Date();
  user.lastLoginAt = new Date();
  user.loginCount = Number(user.loginCount || 0) + 1;
  await user.save();
  setSessionCookie(res, sessionToken(user));
  return res.json({ user: publicTeacher(user) });
}

async function performLogin(req, res, allowedRole) {
  const loginName = String(req.body?.username ?? req.body?.nationalId ?? "").trim();
  if (!allowedRole && loginName.toLowerCase() === "sampad") {
    return performEnvironmentAdminLogin(req, res);
  }
  const nationalId = normalizeDigits(loginName);
  const password = String(req.body?.password || "");
  const user = !allowedRole && loginName.toLowerCase() === "sampad"
    ? await Teacher.findOne({ role: "admin", active: true }).select("+passwordHash")
    : await Teacher.findOne({ nationalId }).select("+passwordHash");
  const valid =
    !!user &&
    user.active &&
    (!allowedRole || user.role === allowedRole) &&
    password.length <= 128 &&
    (await argon2.verify(user.passwordHash, password).catch(() => false));
  if (!valid) return res.status(401).json({ error: "نام کاربری/کد ملی یا رمز عبور درست نیست." });
  user.lastSeenAt = new Date();
  user.lastLoginAt = new Date();
  user.loginCount = Number(user.loginCount || 0) + 1;
  await user.save();
  setSessionCookie(res, sessionToken(user));
  res.json({ user: publicTeacher(user) });
}

app.post("/api/login", authLimiter, async (req, res) => performLogin(req, res));
app.post(DESKTOP_MANAGER_CONNECT_PATH, managerConnectLimiter, performEnvironmentAdminLogin);
app.post("/api/teacher/login", authLimiter, async (req, res) =>
  performLogin(req, res, "teacher"),
);

app.post("/api/logout", (_req, res) => {
  clearSessionCookie(res);
  res.status(204).end();
});

app.get("/api/me", auth, async (req, res) => {
  req.user.lastSeenAt = new Date();
  await req.user.save();
  res.json({ user: publicTeacher(req.user) });
});

app.patch("/api/me", auth, writeLimiter, async (req, res) => {
  const parsed = profileSchema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ error: "اطلاعات حساب معتبر نیست." });
  const before = {
    firstName: req.user.firstName,
    lastName: req.user.lastName,
    phone: req.user.phone,
  };
  Object.assign(req.user, parsed.data);
  await req.user.save();
  await AdminAudit.create({
    action: "profile_updated",
    targetType: "teacher",
    targetId: String(req.user._id),
    summary: "اطلاعات حساب توسط معلم ویرایش شد.",
    oldValue: before,
    newValue: parsed.data,
    result: "saved",
    actorId: req.user._id,
    actorName: `${req.user.firstName} ${req.user.lastName}`,
  });
  res.json({ ok: true, user: publicTeacher(req.user) });
});

app.post("/api/me/password", auth, writeLimiter, async (req, res) => {
  const parsed = passwordSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ error: "رمز تازه باید دست‌کم ۶ نویسه داشته باشد." });
  }
  const user = await Teacher.findById(req.user._id).select("+passwordHash");
  const valid = await argon2.verify(user.passwordHash, parsed.data.currentPassword).catch(() => false);
  if (!valid) {
    await AdminAudit.create({
      action: "password_change_rejected",
      targetType: "teacher",
      targetId: String(user._id),
      summary: "تغییر رمز با رمز فعلی نادرست رد شد.",
      result: "rejected",
      actorId: user._id,
      actorName: `${user.firstName} ${user.lastName}`,
    });
    return res.status(403).json({ error: "رمز فعلی درست نیست." });
  }
  user.passwordHash = await argon2.hash(parsed.data.newPassword, ARGON_OPTIONS);
  user.tokenVersion = Number(user.tokenVersion || 0) + 1;
  await user.save();
  setSessionCookie(res, sessionToken(user));
  await AdminAudit.create({
    action: "password_changed",
    targetType: "teacher",
    targetId: String(user._id),
    summary: "رمز حساب تغییر کرد و نشست‌های قبلی باطل شدند.",
    result: "saved",
    actorId: user._id,
    actorName: `${user.firstName} ${user.lastName}`,
  });
  res.json({ ok: true, user: publicTeacher(user) });
});

// ---------------------------------------------------------------------------
// Teacher endpoints
// ---------------------------------------------------------------------------

async function classesAndSubjects() {
  const cfg = await getBootstrapConfig();
  return {
    classes: cfg?.value?.classes || [],
    subjects: cfg?.value?.subjects || [],
  };
}

app.get("/api/teacher/classes", auth, async (req, res) => {
  const cfg = await classesAndSubjects();
  const ids = new Set(req.user.assignments.map((item) => item.classId));
  res.json({
    classes: cfg.classes.filter((item) => ids.has(item.id)),
    assignments: req.user.assignments,
  });
});

app.get("/api/teacher/roster", auth, async (req, res) => {
  const classId = cleanText(req.query.classId, 120);
  const assignments = req.user.assignments.filter((item) => item.classId === classId);
  if (!assignments.length) return res.status(403).json({ error: "این کلاس در دسترسی حساب شما نیست." });
  const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
  const limit = Math.min(200, Math.max(1, Number.parseInt(req.query.limit, 10) || 200));
  const query = {
    deleted: false,
    $or: [{ classId }, { "data.classId": classId }],
  };
  const [total, docs] = await Promise.all([
    Student.countDocuments(query),
    Student.find(query)
      .sort({ lastName: 1, firstName: 1, nationalId: 1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean(),
  ]);
  res.json({
    students: docs.map(serializeStudent),
    assignments,
    page,
    total,
    hasMore: page * limit < total,
  });
});

app.get("/api/teacher/reports", auth, async (req, res) => {
  const classId = cleanText(req.query.classId, 120);
  const academicYear = cleanText(req.query.academicYear, 40);
  const reportType = cleanText(req.query.reportType, 120);
  const assignments = req.user.assignments.filter((item) => item.classId === classId);
  if (!assignments.length) return res.status(403).json({ error: "این کلاس در دسترسی حساب شما نیست." });
  if (!academicYear || !reportType) {
    return res.status(400).json({ error: "برای دریافت کارنامه‌ها، سال تحصیلی و موضوع آزمون لازم است." });
  }
  const subjects = new Set(assignments.map((item) => item.subjectId));
  const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
  const limit = Math.min(200, Math.max(1, Number.parseInt(req.query.limit, 10) || 200));
  const query = {
    classId,
    academicYear,
    deleted: false,
    $or: [{ reportKey: reportKeyOf(reportType) }, { reportKey: "" }, { reportType }],
  };
  const [total, docs] = await Promise.all([
    Report.countDocuments(query),
    Report.find(query)
      .sort({ id: 1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean(),
  ]);
  res.json({
    reports: docs.map((doc) => {
      const report = serializeReport(doc);
      return {
        id: report.id,
        nationalId: report.nationalId,
        classId: report.classId,
        firstName: report.firstName,
        lastName: report.lastName,
        academicYear: report.academicYear,
        reportType: report.reportType,
        totalScore: report.totalScore,
        scores: Object.fromEntries(
          Object.entries(report.scores || {}).filter(([subjectId]) => subjects.has(subjectId)),
        ),
        subjectSnapshot: (report.subjectSnapshot || []).filter((item) => subjects.has(item.id)),
        scoreActors: Object.fromEntries(
          Object.entries(report.scoreActors || {}).filter(([subjectId]) => subjects.has(subjectId)),
        ),
        updatedAt: report.updatedAt,
        revision: report.revision,
      };
    }),
    page,
    total,
    hasMore: page * limit < total,
  });
});

const isSafeKey = (value) =>
  typeof value === "string" &&
  value.length > 0 &&
  value.length <= 120 &&
  !["__proto__", "prototype", "constructor"].includes(value) &&
  !value.startsWith("$");

function normalizeScore(value) {
  if (value === "" || value === null || value === undefined) return { clear: true, value: null };
  const score = Number(normalizeDigits(value));
  if (Number.isFinite(score) && score >= 0 && score <= 20) return { clear: false, value: score };
  if (score === -1 || score === -2) return { clear: false, value: score };
  return { invalid: true };
}

function calculateTotal(scores, snapshot) {
  const weighted = Object.entries(scores)
    .map(([subjectId, raw]) => {
      const weight = Number(snapshot.find((item) => item.id === subjectId)?.coefficient) || 0;
      return { raw: Number(raw), weight };
    })
    .filter((item) => item.raw !== -1 && item.weight > 0)
    .map((item) => ({ value: item.raw === -2 ? 0 : item.raw, weight: item.weight }));
  const totalWeight = weighted.reduce((sum, item) => sum + item.weight, 0);
  if (!totalWeight) return null;
  const total = weighted.reduce((sum, item) => sum + item.value * item.weight, 0) / totalWeight;
  return Math.round(total * 100) / 100;
}

async function auditScore(entries) {
  if (!entries.length) return;
  try {
    await ScoreAudit.insertMany(entries, { ordered: false });
  } catch (error) {
    console.error("Score audit failed:", error.message);
  }
}

function filteredReportForTeacher(report, subjects) {
  const data = serializeReport(report);
  return {
    ...data,
    scores: Object.fromEntries(
      Object.entries(data.scores || {}).filter(([subjectId]) => subjects.has(subjectId)),
    ),
    subjectSnapshot: (data.subjectSnapshot || []).filter((item) => subjects.has(item.id)),
    scoreActors: Object.fromEntries(
      Object.entries(data.scoreActors || {}).filter(([subjectId]) => subjects.has(subjectId)),
    ),
  };
}

app.put("/api/teacher/reports/:id", auth, writeLimiter, async (req, res) => {
  const body = req.body;
  if (!isPlainObject(body)) return res.status(400).json({ error: "ساختار کارنامه معتبر نیست." });
  const classId = cleanText(body.classId, 120);
  const allowedAssignments = req.user.assignments.filter((item) => item.classId === classId);
  const allowed = new Set(allowedAssignments.map((item) => item.subjectId));
  if (!allowed.size || String(body.id || "") !== String(req.params.id)) {
    return res.status(403).json({ error: "دسترسی ثبت نمره برای این کلاس ندارید." });
  }

  const nationalId = normalizeDigits(body.nationalId);
  const academicYear = cleanText(body.academicYear, 40);
  const reportType = cleanText(body.reportType || "کارنامه", 120);
  if (!/^\d{10}$/.test(nationalId) || !academicYear || !reportType) {
    return res.status(400).json({ error: "شناسه دانش‌آموز، سال تحصیلی و موضوع کارنامه الزامی است." });
  }

  const student = await Student.findOne({ nationalId, deleted: false }).lean();
  if (!student || (student.classId || student.data?.classId) !== classId) {
    return res.status(404).json({ error: "دانش‌آموز در این کلاس پیدا نشد." });
  }

  const cfg = await getBootstrapConfig();
  if ((cfg?.value?.archivedYears || []).includes(academicYear)) {
    return res.status(409).json({ error: "این سال تحصیلی بایگانی شده و کارنامه‌های آن قابل ویرایش نیست." });
  }

  const incomingScores = body.scores;
  if (!isPlainObject(incomingScores)) {
    return res.status(400).json({ error: "ساختار نمره‌ها نامعتبر است." });
  }

  const identityKey = identityKeyOf(nationalId, academicYear, reportType);
  let report = await Report.findOne({
    deleted: false,
    $or: [{ id: String(req.params.id) }, { identityKey }],
  });
  const deletedReport = report
    ? null
    : await Report.findOne({
        deleted: true,
        $or: [{ id: String(req.params.id) }, { identityKey }],
      });
  if (deletedReport) {
    return res.status(409).json({ error: "این کارنامه توسط مدیر پاک شده است؛ برای بازگردانی با مدیر تماس بگیرید." });
  }

  const requestedRevision = Number(body.revision);
  if (report && (!Number.isFinite(requestedRevision) || requestedRevision !== report.revision)) {
    const current = filteredReportForTeacher(report, allowed);
    await auditScore(
      Object.entries(incomingScores)
        .filter(([subjectId]) => allowed.has(subjectId))
        .slice(0, 30)
        .map(([subjectId, value]) => ({
          reportId: report.id,
          subjectId,
          subjectName:
            report.data?.subjectSnapshot?.find((item) => item.id === subjectId)?.name ||
            allowedAssignments.find((item) => item.subjectId === subjectId)?.subjectName ||
            "",
          classId,
          academicYear,
          reportType,
          oldValue: report.data?.scores?.[subjectId] ?? null,
          newValue: value === "" || value === null ? null : Number(normalizeDigits(value)),
          action: "rejected",
          result: "rejected",
          reason: "revision_conflict",
          actorId: req.user._id,
          actorName: `${req.user.firstName} ${req.user.lastName}`,
        })),
    );
    return res.status(409).json({
      error: "این کارنامه هم‌زمان تغییر کرده؛ نسخه تازه بارگذاری شد و تغییر شما ذخیره نشد.",
      current,
    });
  }

  const cleanScores = Object.create(null);
  for (const [subjectId, value] of Object.entries(incomingScores)) {
    if (!isSafeKey(subjectId) || !allowed.has(subjectId)) {
      await auditScore([
        {
          reportId: report?.id || String(req.params.id),
          subjectId,
          subjectName: "",
          classId,
          academicYear,
          reportType,
          oldValue: report?.data?.scores?.[subjectId] ?? null,
          newValue: value === "" || value === null ? null : value,
          action: "rejected",
          result: "rejected",
          reason: "subject_not_allowed",
          actorId: req.user._id,
          actorName: `${req.user.firstName} ${req.user.lastName}`,
        },
      ]);
      return res.status(403).json({ error: "برای ثبت این درس مجوز ندارید." });
    }
    const normalized = normalizeScore(value);
    if (normalized.invalid) {
      await auditScore([
        {
          reportId: report?.id || String(req.params.id),
          subjectId,
          subjectName:
            report?.data?.subjectSnapshot?.find((item) => item.id === subjectId)?.name ||
            allowedAssignments.find((item) => item.subjectId === subjectId)?.subjectName ||
            "",
          classId,
          academicYear,
          reportType,
          oldValue: report?.data?.scores?.[subjectId] ?? null,
          newValue: value,
          action: "rejected",
          result: "rejected",
          reason: "invalid_score",
          actorId: req.user._id,
          actorName: `${req.user.firstName} ${req.user.lastName}`,
        },
      ]);
      return res.status(400).json({ error: "نمره باید بین ۰ تا ۲۰ یا کد غیبت -۱/-۲ باشد." });
    }
    cleanScores[subjectId] = normalized;
  }

  const subjectsCatalog = cfg?.value?.subjects || [];
  const snapshot = [...(report?.data?.subjectSnapshot || [])];
  for (const [subjectId] of Object.entries(cleanScores)) {
    if (snapshot.some((item) => item.id === subjectId)) continue;
    const catalogSubject = subjectsCatalog.find((item) => item.id === subjectId);
    snapshot.push({
      id: subjectId,
      name:
        catalogSubject?.name ||
        allowedAssignments.find((item) => item.subjectId === subjectId)?.subjectName ||
        subjectId,
      coefficient: Number(catalogSubject?.coefficient) || 1,
    });
  }

  const scores = { ...(report?.data?.scores || {}) };
  const scoreActors = { ...(report?.data?.scoreActors || {}) };
  const actor = { id: String(req.user._id), name: `${req.user.firstName} ${req.user.lastName}` };
  const audit = [];
  for (const [subjectId, normalized] of Object.entries(cleanScores)) {
    const oldValue = report?.data?.scores?.[subjectId] ?? null;
    const subjectName = snapshot.find((item) => item.id === subjectId)?.name || subjectId;
    if (normalized.clear) {
      if (Object.prototype.hasOwnProperty.call(scores, subjectId)) {
        delete scores[subjectId];
        scoreActors[subjectId] = actor;
        audit.push({
          reportId: report?.id || String(req.params.id),
          subjectId,
          subjectName,
          classId,
          academicYear,
          reportType,
          oldValue,
          newValue: null,
          action: "cleared",
          result: "saved",
          actorId: req.user._id,
          actorName: actor.name,
        });
      }
    } else if (oldValue !== normalized.value) {
      scores[subjectId] = normalized.value;
      scoreActors[subjectId] = actor;
      audit.push({
        reportId: report?.id || String(req.params.id),
        subjectId,
        subjectName,
        classId,
        academicYear,
        reportType,
        oldValue,
        newValue: normalized.value,
        action: "set",
        result: "saved",
        actorId: req.user._id,
        actorName: actor.name,
      });
    }
  }

  const totalScore = calculateTotal(scores, snapshot);
  const now = new Date();
  const data = {
    ...(report?.data || {}),
    ...stripSyncMetadata(body),
    id: report?.id || String(req.params.id),
    nationalId,
    classId,
    firstName: report?.data?.firstName || student.firstName || student.data?.firstName || "",
    lastName: report?.data?.lastName || student.lastName || student.data?.lastName || "",
    academicYear,
    reportType,
    scores,
    scoreActors,
    subjectSnapshot: snapshot,
    totalScore,
    roundingDigits: 2,
    updatedAt: now.toISOString(),
    updatedBy: actor,
  };
  const canonicalId = report?.id || String(req.params.id);
  data.id = canonicalId;
  const reportKey = reportKeyOf(reportType);

  let saved;
  try {
    if (report) {
      saved = await Report.findOneAndUpdate(
        { _id: report._id, revision: report.revision, deleted: false },
        {
          $set: {
            id: canonicalId,
            nationalId,
            classId,
            academicYear,
            reportType,
            reportKey,
            identityKey,
            data,
            updatedAt: now,
            serverUpdatedAt: now,
            updatedBy: actor,
          },
          $inc: { revision: 1 },
        },
        { new: true, runValidators: true },
      );
      if (!saved) {
        await auditScore(
          audit.map((entry) => ({ ...entry, result: "rejected", action: "rejected", reason: "concurrent_change" })),
        );
        const latest = await Report.findOne({ deleted: false, $or: [{ id: canonicalId }, { identityKey }] });
        return res.status(409).json({
          error: "هم‌زمان تغییر دیگری ذخیره شد؛ نسخه تازه را بررسی کنید.",
          current: latest ? filteredReportForTeacher(latest, allowed) : null,
        });
      }
    } else {
      saved = await Report.create({
        id: canonicalId,
        nationalId,
        classId,
        academicYear,
        reportType,
        reportKey,
        identityKey,
        data,
        revision: 1,
        updatedAt: now,
        serverUpdatedAt: now,
        updatedBy: actor,
        deleted: false,
      });
    }
  } catch (error) {
    if (error?.code === 11000) {
      const latest = await Report.findOne({ deleted: false, $or: [{ id: canonicalId }, { identityKey }] });
      return res.status(409).json({
        error: "برای این دانش‌آموز در این سال و موضوع، کارنامه تکراری ثبت نمی‌شود.",
        current: latest ? filteredReportForTeacher(latest, allowed) : null,
      });
    }
    throw error;
  }

  await auditScore(audit.map((entry) => ({ ...entry, reportId: saved.id })));
  await recordChange({
    entityType: "report",
    entityId: saved.id,
    operation: "upsert",
    data: serializeReport(saved),
    revision: saved.revision,
    source: "teacher",
    actor: req.user,
  });
  res.json({
    ok: true,
    report: filteredReportForTeacher(saved, allowed),
    revision: saved.revision,
    teacherName: actor.name,
  });
});

app.delete("/api/teacher/reports/:id", auth, writeLimiter, async (req, res) => {
  const report = await Report.findOne({ id: String(req.params.id), deleted: false });
  if (!report) return res.status(404).json({ error: "کارنامه پیدا نشد." });
  const allowed = req.user.assignments.some((item) => item.classId === report.classId);
  if (!allowed) return res.status(403).json({ error: "این کارنامه در دسترسی حساب شما نیست." });
  const cfg = await getBootstrapConfig();
  if ((cfg?.value?.archivedYears || []).includes(report.academicYear)) {
    return res.status(409).json({ error: "کارنامه سال بایگانی‌شده قابل حذف نیست." });
  }
  const now = new Date();
  const actor = { id: String(req.user._id), name: `${req.user.firstName} ${req.user.lastName}` };
  const updated = await Report.findOneAndUpdate(
    { _id: report._id, revision: report.revision, deleted: false },
    {
      $set: {
        deleted: true,
        deletedAt: now,
        deletedBy: actor,
        serverUpdatedAt: now,
      },
      $inc: { revision: 1 },
    },
    { new: true },
  );
  if (!updated) return res.status(409).json({ error: "کارنامه هم‌زمان تغییر کرد؛ دوباره تلاش کنید." });
  await auditScore([
    {
      reportId: report.id,
      subjectId: "*",
      subjectName: "حذف کارنامه",
      classId: report.classId,
      academicYear: report.academicYear,
      reportType: report.reportType,
      oldValue: report.data?.totalScore ?? null,
      newValue: null,
      action: "deleted",
      result: "saved",
      actorId: req.user._id,
      actorName: actor.name,
    },
  ]);
  await recordChange({
    entityType: "report",
    entityId: report.id,
    operation: "delete",
    data: {
      id: report.id,
      nationalId: report.nationalId,
      academicYear: report.academicYear,
      reportType: report.reportType,
      deletedAt: now.toISOString(),
    },
    revision: updated.revision,
    source: "teacher",
    actor: req.user,
  });
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Change log / tombstones
// ---------------------------------------------------------------------------

async function nextSequence() {
  const counter = await Counter.findOneAndUpdate(
    { key: "sync-seq" },
    { $inc: { value: 1 } },
    { upsert: true, new: true, setDefaultsOnInsert: true },
  );
  return counter.value;
}

async function recordChange({
  entityType,
  entityId,
  operation,
  data = null,
  revision = 0,
  source = "server",
  actor = null,
}) {
  const seq = await nextSequence();
  await SyncChange.create({
    seq,
    entityType,
    entityId,
    operation,
    data,
    revision,
    source,
    actorId: actor?._id || null,
    actorName: actor ? `${actor.firstName || ""} ${actor.lastName || ""}`.trim() : "",
  });
  return seq;
}

async function currentSequence() {
  const latest = await SyncChange.findOne().sort({ seq: -1 }).select("seq").lean();
  return latest?.seq || 0;
}

// ---------------------------------------------------------------------------
// Admin: catalog / accounts / audit / analytics
// ---------------------------------------------------------------------------

const classSchema = z
  .object({
    id: z.string().trim().min(1).max(120),
    label: z.string().trim().max(180).optional(),
    grade: z.union([z.string(), z.number()]).optional(),
    field: z.string().trim().max(80).optional(),
    section: z.union([z.string(), z.number()]).optional(),
  })
  .passthrough();

const subjectSchema = z
  .object({
    id: z.string().trim().min(1).max(120),
    name: z.string().trim().min(1).max(180),
    grade: z.union([z.string(), z.number()]).optional(),
    field: z.string().trim().max(80).optional(),
    coefficient: z.union([z.number(), z.string()]).optional(),
  })
  .passthrough();

function sanitizeCatalog(classesInput, subjectsInput) {
  const classes = [];
  const subjects = [];
  if (Array.isArray(classesInput)) {
    const seen = new Set();
    for (const item of classesInput.slice(0, 200)) {
      const parsed = classSchema.safeParse(item);
      if (!parsed.success || seen.has(parsed.data.id)) continue;
      seen.add(parsed.data.id);
      classes.push(parsed.data);
    }
  }
  if (Array.isArray(subjectsInput)) {
    const seen = new Set();
    for (const item of subjectsInput.slice(0, 2000)) {
      const parsed = subjectSchema.safeParse(item);
      if (!parsed.success || seen.has(parsed.data.id)) continue;
      seen.add(parsed.data.id);
      const coefficient = Number(parsed.data.coefficient);
      subjects.push({
        ...parsed.data,
        coefficient: Number.isFinite(coefficient) && coefficient > 0 ? coefficient : 1,
      });
    }
  }
  return { classes, subjects };
}

app.get("/api/admin/bootstrap", auth, adminOnly, async (_req, res) => {
  const cfg = await getBootstrapConfig();
  res.json({
    hasSecurityCode: !!cfg?.value?.securityCodeHash,
    classes: cfg?.value?.classes || [],
    subjects: cfg?.value?.subjects || [],
    archivedYears: cfg?.value?.archivedYears || [],
    updatedAt: cfg?.updatedAt || null,
  });
});

app.put("/api/admin/bootstrap", auth, adminOnly, writeLimiter, async (req, res) => {
  const code = normalizeDigits(req.body?.securityCode);
  if (req.body?.securityCode !== undefined && !/^\d{6}$/.test(code)) {
    return res.status(400).json({ error: "کد امنیتی باید دقیقاً شش رقم باشد." });
  }
  const existing = await getBootstrapConfig();
  if (!existing?.value?.securityCodeHash && !code) {
    return res.status(400).json({ error: "برای نخستین راه‌اندازی، کد امنیتی شش‌رقمی لازم است." });
  }
  const previous = existing?.value || {};
  const { classes, subjects } = sanitizeCatalog(
    Array.isArray(req.body?.classes) ? req.body.classes : previous.classes,
    Array.isArray(req.body?.subjects) ? req.body.subjects : previous.subjects,
  );
  const value = {
    ...previous,
    classes,
    subjects,
    archivedYears: Array.isArray(req.body?.archivedYears)
      ? [...new Set(req.body.archivedYears.map((item) => cleanText(item, 40)).filter(Boolean))].slice(0, 100)
      : previous.archivedYears || [],
  };
  if (code) value.securityCodeHash = await argon2.hash(code, ARGON_OPTIONS);
  await Config.findOneAndUpdate(
    { key: "public-bootstrap" },
    { $set: { value, updatedAt: new Date() } },
    { upsert: true, runValidators: true },
  );
  await AdminAudit.create({
    action: "catalog_updated",
    targetType: "config",
    targetId: "public-bootstrap",
    summary: `کد امنیتی ${code ? "تغییر کرد" : "دست نخورد"}؛ ${classes.length} کلاس و ${subjects.length} درس ذخیره شد.`,
    oldValue: {
      classes: previous.classes?.length || 0,
      subjects: previous.subjects?.length || 0,
      hasSecurityCode: !!previous.securityCodeHash,
    },
    newValue: {
      classes: classes.length,
      subjects: subjects.length,
      hasSecurityCode: !!value.securityCodeHash,
    },
    result: "saved",
    actorId: req.user._id,
    actorName: `${req.user.firstName} ${req.user.lastName}`,
  });
  res.json({ ok: true, hasSecurityCode: !!value.securityCodeHash, classes, subjects });
});

app.get("/api/admin/teachers", auth, adminOnly, async (req, res) => {
  const q = cleanText(req.query.q, 80);
  const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
  const limit = Math.min(100, Math.max(1, Number.parseInt(req.query.limit, 10) || 25));
  const filter = {};
  if (q) {
    const rx = new RegExp(escapeRegex(normalizeDigits(q)), "i");
    filter.$or = [{ nationalId: rx }, { firstName: rx }, { lastName: rx }, { phone: rx }];
  }
  const [total, users] = await Promise.all([
    Teacher.countDocuments(filter),
    Teacher.find(filter)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean(),
  ]);
  const ids = users.map((user) => user._id);
  const audits = await ScoreAudit.aggregate([
    { $match: { actorId: { $in: ids }, result: "saved" } },
    {
      $group: {
        _id: "$actorId",
        scores: { $sum: 1 },
        lastScoreAt: { $max: "$createdAt" },
      },
    },
  ]);
  const rejected = await ScoreAudit.aggregate([
    { $match: { actorId: { $in: ids }, result: "rejected" } },
    { $group: { _id: "$actorId", rejected: { $sum: 1 } } },
  ]);
  const map = new Map(audits.map((item) => [String(item._id), item]));
  const rejectedMap = new Map(rejected.map((item) => [String(item._id), item.rejected]));
  res.json({
    users: users.map((user) => ({
      ...publicTeacher(user),
      scoreActivity: {
        scores: map.get(String(user._id))?.scores || 0,
        lastScoreAt: map.get(String(user._id))?.lastScoreAt || null,
        rejected: rejectedMap.get(String(user._id)) || 0,
      },
    })),
    page,
    total,
    hasMore: page * limit < total,
  });
});

app.patch("/api/admin/teachers/:id", auth, adminOnly, writeLimiter, async (req, res) => {
  const user = await Teacher.findById(req.params.id);
  if (!user) return res.status(404).json({ error: "کاربر پیدا نشد." });
  const before = {
    active: user.active,
    role: user.role,
    assignments: user.assignments.map((item) => ({
      classId: item.classId,
      subjectId: item.subjectId,
      subjectName: item.subjectName,
    })),
  };
  const patch = {};
  if (typeof req.body?.active === "boolean") patch.active = req.body.active;
  if (req.body?.role !== undefined) {
    if (!["admin", "teacher"].includes(req.body.role)) {
      return res.status(400).json({ error: "نقش نامعتبر است." });
    }
    patch.role = req.body.role;
  }
  if (Array.isArray(req.body?.assignments)) {
    const cfg = await getBootstrapConfig();
    const classes = cfg?.value?.classes || [];
    const subjects = cfg?.value?.subjects || [];
    const valid = [];
    const seen = new Set();
    for (const assignment of req.body.assignments.slice(0, 100)) {
      const klass = classes.find((item) => item.id === cleanText(assignment?.classId, 120));
      const subject = subjects.find(
        (item) =>
          item.id === cleanText(assignment?.subjectId, 120) &&
          (!item.grade || Number(item.grade) === Number(klass?.grade)) &&
          (!item.field || item.field === klass?.field),
      );
      if (!klass || !subject) continue;
      const key = `${klass.id}|${subject.id}`;
      if (seen.has(key)) continue;
      seen.add(key);
      valid.push({
        classId: klass.id,
        subjectId: subject.id,
        subjectName: subject.name,
        grade: String(klass.grade || subject.grade || ""),
        field: String(klass.field || subject.field || ""),
      });
    }
    patch.assignments = valid;
  }
  const losingAdmin =
    (patch.active === false || patch.role === "teacher") && user.role === "admin";
  if (losingAdmin) {
    if (String(user._id) === String(req.user._id)) {
      return res.status(409).json({ error: "مدیر جاری نمی‌تواند نقش یا وضعیت خودش را محدود کند." });
    }
    const activeAdmins = await Teacher.countDocuments({ role: "admin", active: true });
    if (activeAdmins <= 1) {
      return res.status(409).json({ error: "حداقل یک مدیر فعال باید باقی بماند." });
    }
  }
  Object.assign(user, patch);
  await user.save();
  await AdminAudit.create({
    action:
      patch.active !== undefined
        ? patch.active
          ? "account_activated"
          : "account_deactivated"
        : patch.role
          ? "role_changed"
          : "assignments_changed",
    targetType: "teacher",
    targetId: String(user._id),
    summary: `${user.firstName} ${user.lastName}`,
    oldValue: before,
    newValue: {
      active: user.active,
      role: user.role,
      assignments: user.assignments.map((item) => ({
        classId: item.classId,
        subjectId: item.subjectId,
        subjectName: item.subjectName,
      })),
    },
    result: "saved",
    actorId: req.user._id,
    actorName: `${req.user.firstName} ${req.user.lastName}`,
  });
  res.json({ user: publicTeacher(user) });
});

app.get("/api/admin/audit", auth, adminOnly, async (req, res) => {
  const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
  const limit = Math.min(100, Math.max(1, Number.parseInt(req.query.limit, 10) || 25));
  const filter = {};
  if (req.query.teacherId && mongoose.isValidObjectId(req.query.teacherId)) {
    filter.actorId = req.query.teacherId;
  }
  if (["saved", "rejected", "failed"].includes(req.query.result)) filter.result = req.query.result;
  if (req.query.q) {
    const rx = new RegExp(escapeRegex(cleanText(req.query.q, 80)), "i");
    filter.$or = [{ actorName: rx }, { subjectName: rx }, { reportId: rx }];
  }
  const adminFilter = req.query.teacherId && mongoose.isValidObjectId(req.query.teacherId)
    ? { actorId: req.query.teacherId }
    : {};
  if (req.query.type === "admin") {
    const [total, items] = await Promise.all([
      AdminAudit.countDocuments(adminFilter),
      AdminAudit.find(adminFilter)
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean(),
    ]);
    return res.json({
      items: [],
      adminItems: items,
      page,
      total,
      hasMore: page * limit < total,
    });
  }
  const [total, items, adminItems] = await Promise.all([
    ScoreAudit.countDocuments(filter),
    ScoreAudit.find(filter)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean(),
    AdminAudit.find(adminFilter).sort({ createdAt: -1 }).limit(20).lean(),
  ]);
  res.json({
    items,
    adminItems,
    page,
    total,
    hasMore: page * limit < total,
  });
});

app.get("/api/admin/students", auth, adminOnly, async (req, res) => {
  const q = cleanText(req.query.q, 80);
  const classId = cleanText(req.query.classId, 120);
  const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
  const limit = Math.min(100, Math.max(1, Number.parseInt(req.query.limit, 10) || 25));
  const filter = { deleted: false };
  if (classId) filter.$and = [{ $or: [{ classId }, { "data.classId": classId }] }];
  if (q) {
    const rx = new RegExp(escapeRegex(normalizeDigits(q)), "i");
    filter.$or = [
      { nationalId: rx },
      { firstName: rx },
      { lastName: rx },
      { "data.firstName": rx },
      { "data.lastName": rx },
    ];
  }
  const [total, students] = await Promise.all([
    Student.countDocuments(filter),
    Student.find(filter)
      .sort({ lastName: 1, firstName: 1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean(),
  ]);
  const ids = students.map((student) => student.nationalId);
  const counts = await Report.aggregate([
    { $match: { nationalId: { $in: ids }, deleted: false } },
    { $group: { _id: "$nationalId", count: { $sum: 1 } } },
  ]);
  const countMap = new Map(counts.map((item) => [item._id, item.count]));
  res.json({
    students: students.map((student) => ({
      ...serializeStudent(student),
      reportCount: countMap.get(student.nationalId) || 0,
    })),
    page,
    total,
    hasMore: page * limit < total,
  });
});

app.get("/api/admin/students/:nationalId/analytics", auth, adminOnly, async (req, res) => {
  const nationalId = normalizeDigits(req.params.nationalId);
  if (!/^\d{10}$/.test(nationalId)) return res.status(400).json({ error: "کد ملی معتبر نیست." });
  const student = await Student.findOne({ nationalId, deleted: false }).lean();
  if (!student) return res.status(404).json({ error: "دانش‌آموز پیدا نشد." });
  const reportType = cleanText(req.query.reportType, 120);
  const academicYear = cleanText(req.query.academicYear, 40);
  const all = await Report.find({ nationalId, deleted: false }).sort({ academicYear: 1, updatedAt: 1 }).lean();
  const topics = [...new Set(all.map((report) => report.reportType).filter(Boolean))];
  const years = [...new Set(all.map((report) => report.academicYear).filter(Boolean))];
  if (!reportType) {
    res.json({
      student: serializeStudent(student),
      topics,
      years,
      reports: all.map((report) => ({
        id: report.id,
        academicYear: report.academicYear,
        reportType: report.reportType,
        classId: report.classId,
        totalScore: report.data?.totalScore ?? null,
        updatedAt: report.updatedAt,
      })),
      subjects: [],
    });
    return;
  }
  const key = reportKeyOf(reportType);
  const filtered = all.filter(
    (report) =>
      reportKeyOf(report.reportType) === key &&
      (!academicYear || report.academicYear === academicYear),
  );
  const subjectMap = new Map();
  for (const report of filtered) {
    const snapshot = report.data?.subjectSnapshot || [];
    const scores = report.data?.scores || {};
    for (const [subjectId, raw] of Object.entries(scores)) {
      const value = Number(raw);
      if (!Number.isFinite(value)) continue;
      const meta = snapshot.find((item) => item.id === subjectId);
      if (!subjectMap.has(subjectId)) {
        subjectMap.set(subjectId, {
          id: subjectId,
          name: meta?.name || subjectId,
          coefficient: Number(meta?.coefficient) || 1,
          points: [],
        });
      }
      const entry = subjectMap.get(subjectId);
      const counted = value === -1 ? null : value === -2 ? 0 : value;
      entry.points.push({
        reportId: report.id,
        academicYear: report.academicYear,
        reportType: report.reportType,
        score: value,
        counted,
        createdAt: report.updatedAt,
      });
    }
  }
  const subjects = [...subjectMap.values()].map((subject) => {
    const counted = subject.points.filter((point) => point.counted !== null);
    return {
      ...subject,
      average: counted.length
        ? Math.round(
            (counted.reduce((sum, point) => sum + point.counted, 0) / counted.length) * 100,
          ) / 100
        : null,
      trend:
        counted.length >= 2
          ? Math.round((counted.at(-1).counted - counted[0].counted) * 100) / 100
          : null,
    };
  });
  res.json({
    student: serializeStudent(student),
    scope: { reportType, academicYear: academicYear || null },
    topics,
    years,
    reports: filtered.map((report) => ({
      id: report.id,
      academicYear: report.academicYear,
      reportType: report.reportType,
      classId: report.classId,
      totalScore: report.data?.totalScore ?? null,
      updatedAt: report.updatedAt,
    })),
    subjects,
  });
});

app.get("/api/admin/overview", auth, adminOnly, async (_req, res) => {
  const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  const [
    studentCount,
    reportCount,
    teacherCount,
    adminCount,
    activeToday,
    activeWeek,
    recentScores,
    recentAdmin,
    recentStudents,
  ] = await Promise.all([
    Student.countDocuments({ deleted: false }),
    Report.countDocuments({ deleted: false }),
    Teacher.countDocuments({ role: "teacher" }),
    Teacher.countDocuments({ role: "admin", active: true }),
    Teacher.countDocuments({ lastSeenAt: { $gte: dayAgo } }),
    Teacher.countDocuments({ lastSeenAt: { $gte: weekAgo } }),
    ScoreAudit.find({ result: "saved" }).sort({ createdAt: -1 }).limit(10).lean(),
    AdminAudit.find().sort({ createdAt: -1 }).limit(10).lean(),
    Student.find({ deleted: false }).sort({ updatedAt: -1 }).limit(5).lean(),
  ]);
  res.json({
    studentCount,
    reportCount,
    teacherCount,
    adminCount,
    activeToday,
    activeWeek,
    recentScores,
    recentAdmin,
    recentStudents: recentStudents.map(serializeStudent),
    version: APP_VERSION,
  });
});

// ---------------------------------------------------------------------------
// Admin sync protocol v2
// ---------------------------------------------------------------------------

const syncTombstoneStudentSchema = z
  .object({
    nationalId: z.string().trim().regex(/^\d{10}$/),
    deletedAt: z.string().optional(),
  })
  .passthrough();

const syncTombstoneReportSchema = z
  .object({
    id: z.string().trim().min(1).max(160),
    nationalId: z.string().trim().regex(/^\d{10}$/).optional(),
    academicYear: z.string().trim().max(40).optional(),
    reportType: z.string().trim().max(120).optional(),
    deletedAt: z.string().optional(),
  })
  .passthrough();

const syncPayloadSchema = z
  .object({
    protocol: z.number().optional(),
    students: z.array(z.record(z.any())).max(500).optional(),
    reports: z.array(z.record(z.any())).max(300).optional(),
    classes: z.array(z.any()).max(200).optional(),
    subjects: z.array(z.any()).max(2000).optional(),
    settings: z.record(z.any()).optional(),
    archivedYears: z.array(z.string()).max(100).optional(),
    tombstones: z
      .object({
        students: z.array(syncTombstoneStudentSchema).max(500).optional(),
        reports: z.array(syncTombstoneReportSchema).max(500).optional(),
      })
      .optional(),
    force: z
      .object({
        students: z.array(z.string()).max(500).optional(),
        reports: z.array(z.string()).max(500).optional(),
      })
      .optional(),
  })
  .passthrough();

const cleanSharedSettings = (settings) => {
  const clean = { ...(isPlainObject(settings) ? settings : {}) };
  for (const key of [
    "credential",
    "sessionUntil",
    "locked",
    "siteSessionCookie",
    "siteAdminName",
    "siteServerUrl",
    "siteSecurityCodeSet",
    "siteSecurityCodeUpdatedAt",
    "siteLastSyncAt",
    "siteCursor",
    "syncProtocol",
    "syncConflicts",
    "siteConflictNotice",
    "lastSyncConflictNotice",
    "failedLogins",
    "loginLockUntil",
    "loginNextAllowedAt",
    "password",
    "adminPassword",
  ]) {
    delete clean[key];
  }
  return clean;
};

function conflictPayload({ type, id, nationalId, reason, message, local, remote }) {
  return {
    type,
    id,
    nationalId,
    reason,
    message,
    local,
    remote,
    detectedAt: new Date().toISOString(),
  };
}

async function upsertStudentFromDesktop(record, { actor, force }) {
  const nationalId = normalizeDigits(record?.nationalId);
  if (!/^\d{10}$/.test(nationalId)) return { accepted: null, conflict: null };
  const incoming = stripSyncMetadata(record);
  const classId = cleanText(incoming.classId, 120);
  incoming.nationalId = nationalId;
  incoming.classId = classId;
  incoming.firstName = cleanText(incoming.firstName, 120);
  incoming.lastName = cleanText(incoming.lastName, 120);
  const incomingTime = toDate(incoming.updatedAt);
  incoming.updatedAt = incomingTime.toISOString();

  const existing = await Student.findOne({ nationalId });
  if (existing?.deleted) {
    const deletedAt = existing.deletedAt || existing.updatedAt;
    if (!force && incomingTime.getTime() <= new Date(deletedAt).getTime()) {
      return {
        accepted: null,
        conflict: conflictPayload({
          type: "student",
          id: nationalId,
          nationalId,
          reason: "deleted_remote",
          message: "این دانش‌آموز در سایت حذف شده است؛ بازگردانی فقط با تأیید مدیر.",
          local: record,
          remote: null,
        }),
      };
    }
  }

  const remote = existing && !existing.deleted ? serializeStudent(existing) : null;
  if (remote && sameData(comparableContent(remote), comparableContent(incoming))) {
    return {
      accepted: { type: "student", id: nationalId, nationalId, revision: existing.revision },
      conflict: null,
    };
  }

  const baseRevision = Number(record?.siteRevision);
  if (remote && !force) {
    if (Number.isFinite(baseRevision)) {
      if (baseRevision !== existing.revision) {
        return {
          accepted: null,
          conflict: conflictPayload({
            type: "student",
            id: nationalId,
            nationalId,
            reason: "revision_conflict",
            message: "این دانش‌آموز پس از آخرین همگام‌سازی در سایت تغییر کرده است.",
            local: record,
            remote,
          }),
        };
      }
    } else if (incomingTime.getTime() < existing.updatedAt.getTime()) {
      return {
        accepted: null,
        conflict: conflictPayload({
          type: "student",
          id: nationalId,
          nationalId,
          reason: "older_remote",
          message: "نسخه سایت تازه‌تر از نسخه برنامه است.",
          local: record,
          remote,
        }),
      };
    }
  }

  const now = new Date();
  let saved;
  if (existing) {
    const filter = { _id: existing._id };
    if (!force) filter.revision = existing.revision;
    saved = await Student.findOneAndUpdate(
      filter,
      {
        $set: {
          nationalId,
          classId,
          firstName: incoming.firstName,
          lastName: incoming.lastName,
          data: incoming,
          updatedAt: incomingTime,
          serverUpdatedAt: now,
          updatedBy: actor ? { id: String(actor._id), name: `${actor.firstName} ${actor.lastName}` } : null,
          deleted: false,
          deletedAt: null,
          deletedBy: null,
        },
        $inc: { revision: 1 },
      },
      { new: true, runValidators: true },
    );
    if (!saved) {
      const latest = await Student.findOne({ nationalId });
      return {
        accepted: null,
        conflict: conflictPayload({
          type: "student",
          id: nationalId,
          nationalId,
          reason: "concurrent_change",
          message: "هم‌زمان تغییر دیگری روی سایت ذخیره شد.",
          local: record,
          remote: latest && !latest.deleted ? serializeStudent(latest) : null,
        }),
      };
    }
  } else {
    saved = await Student.create({
      nationalId,
      classId,
      firstName: incoming.firstName,
      lastName: incoming.lastName,
      data: incoming,
      revision: 1,
      updatedAt: incomingTime,
      serverUpdatedAt: now,
      updatedBy: actor ? { id: String(actor._id), name: `${actor.firstName} ${actor.lastName}` } : null,
      deleted: false,
    });
  }
  await recordChange({
    entityType: "student",
    entityId: nationalId,
    operation: "upsert",
    data: serializeStudent(saved),
    revision: saved.revision,
    source: "desktop",
    actor,
  });
  return {
    accepted: { type: "student", id: nationalId, nationalId, revision: saved.revision },
    conflict: null,
  };
}

async function upsertReportFromDesktop(record, { actor, force }) {
  const nationalId = normalizeDigits(record?.nationalId);
  const academicYear = cleanText(record?.academicYear, 40);
  const reportType = cleanText(record?.reportType || "کارنامه", 120);
  const requestedId = cleanText(record?.id, 160);
  if (!/^\d{10}$/.test(nationalId) || !academicYear || !requestedId) return { accepted: null, conflict: null };
  const identityKey = identityKeyOf(nationalId, academicYear, reportType);
  const incoming = stripSyncMetadata(record);
  incoming.nationalId = nationalId;
  incoming.academicYear = academicYear;
  incoming.reportType = reportType;
  incoming.id = requestedId;
  incoming.classId = cleanText(incoming.classId, 120);
  const incomingTime = toDate(incoming.updatedAt || incoming.createdAt);
  incoming.updatedAt = incomingTime.toISOString();

  const existing = await Report.findOne({
    $or: [{ id: requestedId }, { identityKey }],
  });
  if (existing?.deleted) {
    const deletedAt = existing.deletedAt || existing.updatedAt;
    if (!force && incomingTime.getTime() <= new Date(deletedAt).getTime()) {
      return {
        accepted: null,
        conflict: conflictPayload({
          type: "report",
          id: requestedId,
          nationalId,
          reason: "deleted_remote",
          message: "این کارنامه در سایت حذف شده است؛ بازگردانی فقط با تأیید مدیر.",
          local: record,
          remote: null,
        }),
      };
    }
  }

  const remote = existing && !existing.deleted ? serializeReport(existing) : null;
  const canonicalId = existing?.id || requestedId;
  incoming.id = canonicalId;
  if (remote && sameData(comparableContent(remote), comparableContent(incoming))) {
    return {
      accepted: {
        type: "report",
        id: canonicalId,
        requestedId,
        nationalId,
        revision: existing.revision,
      },
      conflict: null,
    };
  }

  const baseRevision = Number(record?.siteRevision);
  if (remote && !force) {
    if (Number.isFinite(baseRevision)) {
      if (baseRevision !== existing.revision) {
        return {
          accepted: null,
          conflict: conflictPayload({
            type: "report",
            id: canonicalId,
            nationalId,
            reason: "revision_conflict",
            message: "این کارنامه پس از آخرین همگام‌سازی توسط معلم تغییر کرده است.",
            local: record,
            remote,
          }),
        };
      }
    } else if (
      incomingTime.getTime() < existing.updatedAt.getTime() &&
      (existing.updatedBy?.id ? String(existing.updatedBy.id) !== String(actor?._id || "") : true)
    ) {
      return {
        accepted: null,
        conflict: conflictPayload({
          type: "report",
          id: canonicalId,
          nationalId,
          reason: "older_remote",
          message: "نسخه سایت تازه‌تر از نسخه برنامه است.",
          local: record,
          remote,
        }),
      };
    }
  }

  const now = new Date();
  const data = {
    ...incoming,
    id: canonicalId,
    nationalId,
    classId: incoming.classId,
    academicYear,
    reportType,
    updatedAt: incomingTime.toISOString(),
  };
  const reportKey = reportKeyOf(reportType);
  let saved;
  try {
    if (existing) {
      const filter = { _id: existing._id };
      if (!force) filter.revision = existing.revision;
      saved = await Report.findOneAndUpdate(
        filter,
        {
          $set: {
            id: canonicalId,
            nationalId,
            classId: incoming.classId,
            academicYear,
            reportType,
            reportKey,
            identityKey,
            data,
            updatedAt: incomingTime,
            serverUpdatedAt: now,
            updatedBy: actor ? { id: String(actor._id), name: `${actor.firstName} ${actor.lastName}` } : null,
            deleted: false,
            deletedAt: null,
            deletedBy: null,
          },
          $inc: { revision: 1 },
        },
        { new: true, runValidators: true },
      );
      if (!saved) {
        const latest = await Report.findOne({ $or: [{ id: canonicalId }, { identityKey }] });
        return {
          accepted: null,
          conflict: conflictPayload({
            type: "report",
            id: canonicalId,
            nationalId,
            reason: "concurrent_change",
            message: "هم‌زمان تغییر دیگری روی سایت ذخیره شد.",
            local: record,
            remote: latest && !latest.deleted ? serializeReport(latest) : null,
          }),
        };
      }
    } else {
      saved = await Report.create({
        id: canonicalId,
        nationalId,
        classId: incoming.classId,
        academicYear,
        reportType,
        reportKey,
        identityKey,
        data,
        revision: 1,
        updatedAt: incomingTime,
        serverUpdatedAt: now,
        updatedBy: actor ? { id: String(actor._id), name: `${actor.firstName} ${actor.lastName}` } : null,
        deleted: false,
      });
    }
  } catch (error) {
    if (error?.code === 11000) {
      const latest = await Report.findOne({ $or: [{ id: canonicalId }, { identityKey }] });
      return {
        accepted: null,
        conflict: conflictPayload({
          type: "report",
          id: canonicalId,
          nationalId,
          reason: "duplicate_identity",
          message: "کارنامه تکراری برای همین دانش‌آموز، سال و موضوع وجود دارد.",
          local: record,
          remote: latest && !latest.deleted ? serializeReport(latest) : null,
        }),
      };
    }
    throw error;
  }
  await recordChange({
    entityType: "report",
    entityId: saved.id,
    operation: "upsert",
    data: serializeReport(saved),
    revision: saved.revision,
    source: "desktop",
    actor,
  });
  return {
    accepted: {
      type: "report",
      id: saved.id,
      requestedId,
      nationalId,
      revision: saved.revision,
    },
    conflict: null,
  };
}

async function deleteStudentFromDesktop(tombstone, { actor, force }) {
  const nationalId = normalizeDigits(tombstone?.nationalId);
  if (!/^\d{10}$/.test(nationalId)) return { accepted: null, conflict: null };
  const existing = await Student.findOne({ nationalId });
  if (!existing || existing.deleted) return { accepted: { type: "student", id: nationalId, deleted: true }, conflict: null };
  const deletedAt = toDate(tombstone.deletedAt);
  if (!force && deletedAt.getTime() < existing.updatedAt.getTime()) {
    return {
      accepted: null,
      conflict: conflictPayload({
        type: "student",
        id: nationalId,
        nationalId,
        reason: "delete_conflict",
        message: "این دانش‌آموز پس از زمان حذف در سایت تغییر کرده است؛ حذف انجام نشد.",
        local: { nationalId, deletedAt: deletedAt.toISOString() },
        remote: serializeStudent(existing),
      }),
    };
  }
  const now = new Date();
  const updated = await Student.findOneAndUpdate(
    { _id: existing._id },
    {
      $set: {
        deleted: true,
        deletedAt,
        deletedBy: actor ? { id: String(actor._id), name: `${actor.firstName} ${actor.lastName}` } : null,
        serverUpdatedAt: now,
      },
      $inc: { revision: 1 },
    },
    { new: true },
  );
  await recordChange({
    entityType: "student",
    entityId: nationalId,
    operation: "delete",
    data: { nationalId, deletedAt: deletedAt.toISOString() },
    revision: updated.revision,
    source: "desktop",
    actor,
  });
  const reports = await Report.find({ nationalId, deleted: false });
  for (const report of reports) {
    const reportUpdated = await Report.findOneAndUpdate(
      { _id: report._id, deleted: false },
      {
        $set: {
          deleted: true,
          deletedAt,
          deletedBy: actor ? { id: String(actor._id), name: `${actor.firstName} ${actor.lastName}` } : null,
          serverUpdatedAt: now,
        },
        $inc: { revision: 1 },
      },
      { new: true },
    );
    if (reportUpdated) {
      await recordChange({
        entityType: "report",
        entityId: report.id,
        operation: "delete",
        data: {
          id: report.id,
          nationalId,
          academicYear: report.academicYear,
          reportType: report.reportType,
          deletedAt: deletedAt.toISOString(),
        },
        revision: reportUpdated.revision,
        source: "desktop",
        actor,
      });
    }
  }
  return { accepted: { type: "student", id: nationalId, deleted: true }, conflict: null };
}

async function deleteReportFromDesktop(tombstone, { actor, force }) {
  const id = cleanText(tombstone?.id, 160);
  if (!id) return { accepted: null, conflict: null };
  const identityKey =
    /^\d{10}$/.test(String(tombstone.nationalId || "")) && tombstone.academicYear
      ? identityKeyOf(tombstone.nationalId, tombstone.academicYear, tombstone.reportType || "کارنامه")
      : null;
  const existing = await Report.findOne(
    identityKey ? { $or: [{ id }, { identityKey }] } : { id },
  );
  if (!existing || existing.deleted) return { accepted: { type: "report", id, deleted: true }, conflict: null };
  const deletedAt = toDate(tombstone.deletedAt);
  if (!force && deletedAt.getTime() < existing.updatedAt.getTime()) {
    return {
      accepted: null,
      conflict: conflictPayload({
        type: "report",
        id: existing.id,
        nationalId: existing.nationalId,
        reason: "delete_conflict",
        message: "این کارنامه پس از زمان حذف در سایت تغییر کرده است؛ حذف انجام نشد.",
        local: tombstone,
        remote: serializeReport(existing),
      }),
    };
  }
  const updated = await Report.findOneAndUpdate(
    { _id: existing._id, deleted: false },
    {
      $set: {
        deleted: true,
        deletedAt,
        deletedBy: actor ? { id: String(actor._id), name: `${actor.firstName} ${actor.lastName}` } : null,
        serverUpdatedAt: new Date(),
      },
      $inc: { revision: 1 },
    },
    { new: true },
  );
  if (!updated) return { accepted: { type: "report", id: existing.id, deleted: true }, conflict: null };
  await recordChange({
    entityType: "report",
    entityId: existing.id,
    operation: "delete",
    data: {
      id: existing.id,
      nationalId: existing.nationalId,
      academicYear: existing.academicYear,
      reportType: existing.reportType,
      deletedAt: deletedAt.toISOString(),
    },
    revision: updated.revision,
    source: "desktop",
    actor,
  });
  return { accepted: { type: "report", id: existing.id, deleted: true }, conflict: null };
}

app.post("/api/admin/sync", auth, adminOnly, async (req, res) => {
  const parsed = syncPayloadSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ error: "ساختار بستهٔ همگام‌سازی معتبر نیست." });
  }
  const payload = parsed.data;
  const forceStudents = new Set(
    (payload.force?.students || []).map((item) => normalizeDigits(item)),
  );
  const forceReports = new Set((payload.force?.reports || []).map((item) => String(item)));
  const conflicts = [];
  const accepted = [];
  const actor = req.user;

  for (const tombstone of payload.tombstones?.students || []) {
    const result = await deleteStudentFromDesktop(tombstone, {
      actor,
      force: forceStudents.has(normalizeDigits(tombstone.nationalId)),
    });
    if (result.accepted) accepted.push(result.accepted);
    if (result.conflict) conflicts.push(result.conflict);
  }
  for (const tombstone of payload.tombstones?.reports || []) {
    const force = forceReports.has(String(tombstone.id));
    const result = await deleteReportFromDesktop(tombstone, { actor, force });
    if (result.accepted) accepted.push(result.accepted);
    if (result.conflict) conflicts.push(result.conflict);
  }
  for (const student of payload.students || []) {
    const result = await upsertStudentFromDesktop(student, {
      actor,
      force: forceStudents.has(normalizeDigits(student?.nationalId)),
    });
    if (result.accepted) accepted.push(result.accepted);
    if (result.conflict) conflicts.push(result.conflict);
  }
  for (const report of payload.reports || []) {
    const result = await upsertReportFromDesktop(report, {
      actor,
      force: forceReports.has(String(report?.id)),
    });
    if (result.accepted) accepted.push(result.accepted);
    if (result.conflict) conflicts.push(result.conflict);
  }

  if (
    Array.isArray(payload.classes) ||
    Array.isArray(payload.subjects) ||
    isPlainObject(payload.settings) ||
    Array.isArray(payload.archivedYears)
  ) {
    const cfg = await getBootstrapConfig();
    const previous = cfg?.value || {};
    const { classes, subjects } = sanitizeCatalog(
      Array.isArray(payload.classes) ? payload.classes : previous.classes,
      Array.isArray(payload.subjects) ? payload.subjects : previous.subjects,
    );
    const archivedYears = Array.isArray(payload.archivedYears)
      ? [...new Set(payload.archivedYears.map((item) => cleanText(item, 40)).filter(Boolean))].slice(0, 100)
      : previous.archivedYears || [];
    const catalogValue = {
      ...previous,
      classes,
      subjects,
      archivedYears,
    };
    await Config.findOneAndUpdate(
      { key: "public-bootstrap" },
      { $set: { value: catalogValue, updatedAt: new Date() } },
      { upsert: true },
    );
    const sharedSettings = cleanSharedSettings(payload.settings);
    await Config.findOneAndUpdate(
      { key: "desktop-settings" },
      {
        $set: {
          value: {
            classes,
            subjects,
            settings: sharedSettings,
            archivedYears,
          },
          updatedAt: new Date(),
        },
      },
      { upsert: true },
    );
  }

  if (accepted.length || conflicts.length) {
    await AdminAudit.create({
      action: "desktop_sync",
      targetType: "sync",
      targetId: "",
      summary: `${accepted.length} تغییر پذیرفته شد و ${conflicts.length} تعارض برای بررسی ثبت شد.`,
      oldValue: null,
      newValue: {
        accepted: accepted.length,
        tombstones:
          (payload.tombstones?.students?.length || 0) +
          (payload.tombstones?.reports?.length || 0),
        conflicts: conflicts.length,
      },
      result: "saved",
      actorId: actor._id,
      actorName: `${actor.firstName} ${actor.lastName}`,
    });
  }

  res.json({
    ok: true,
    conflicts,
    accepted,
    cursor: await currentSequence(),
    serverTime: new Date().toISOString(),
  });
});

app.get("/api/admin/changes", auth, adminOnly, async (req, res) => {
  const since = Math.max(0, Number.parseInt(req.query.since, 10) || 0);
  const limit = Math.min(500, Math.max(1, Number.parseInt(req.query.limit, 10) || 200));
  const changes = await SyncChange.find({ seq: { $gt: since } })
    .sort({ seq: 1 })
    .limit(limit + 1)
    .lean();
  const hasMore = changes.length > limit;
  const page = changes.slice(0, limit);
  res.json({
    changes: page.map((change) => ({
      seq: change.seq,
      type: change.entityType,
      operation: change.operation,
      entityId: change.entityId,
      revision: change.revision,
      source: change.source,
      data: change.data,
      createdAt: change.createdAt,
    })),
    cursor: page.length ? page.at(-1).seq : since,
    hasMore,
  });
});

app.get("/api/admin/snapshot", auth, adminOnly, async (req, res) => {
  const type = cleanText(req.query.type, 40) || "meta";
  const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
  const limit = Math.min(250, Math.max(1, Number.parseInt(req.query.limit, 10) || 100));
  if (type === "meta") {
    const cfg = await getBootstrapConfig();
    const desktopCfg = await Config.findOne({ key: "desktop-settings" }).lean();
    return res.json({
      cursor: await currentSequence(),
      classes: cfg?.value?.classes || desktopCfg?.value?.classes || [],
      subjects: cfg?.value?.subjects || desktopCfg?.value?.subjects || [],
      archivedYears: cfg?.value?.archivedYears || desktopCfg?.value?.archivedYears || [],
      settings: desktopCfg?.value?.settings || {},
      counts: {
        students: await Student.countDocuments({ deleted: false }),
        reports: await Report.countDocuments({ deleted: false }),
        tombstones:
          (await Student.countDocuments({ deleted: true })) +
          (await Report.countDocuments({ deleted: true })),
      },
      hasSecurityCode: !!cfg?.value?.securityCodeHash,
    });
  }
  if (type === "students") {
    const [total, docs] = await Promise.all([
      Student.countDocuments({ deleted: false }),
      Student.find({ deleted: false })
        .sort({ nationalId: 1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean(),
    ]);
    return res.json({
      type,
      items: docs.map(serializeStudent),
      page,
      total,
      hasMore: page * limit < total,
    });
  }
  if (type === "reports") {
    const [total, docs] = await Promise.all([
      Report.countDocuments({ deleted: false }),
      Report.find({ deleted: false })
        .sort({ id: 1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean(),
    ]);
    return res.json({
      type,
      items: docs.map(serializeReport),
      page,
      total,
      hasMore: page * limit < total,
    });
  }
  if (type === "tombstones") {
    const [students, reports] = await Promise.all([
      Student.find({ deleted: true })
        .sort({ deletedAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean(),
      Report.find({ deleted: true })
        .sort({ deletedAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean(),
    ]);
    return res.json({
      type,
      students: students.map((doc) => ({
        nationalId: doc.nationalId,
        deletedAt: iso(doc.deletedAt || doc.updatedAt),
      })),
      reports: reports.map((doc) => ({
        id: doc.id,
        nationalId: doc.nationalId,
        academicYear: doc.academicYear,
        reportType: doc.reportType,
        deletedAt: iso(doc.deletedAt || doc.updatedAt),
      })),
      page,
      hasMore: students.length >= limit || reports.length >= limit,
    });
  }
  res.status(400).json({ error: "نوع snapshot معتبر نیست." });
});

// ---------------------------------------------------------------------------
// Static website + error handling
// ---------------------------------------------------------------------------

app.get("/tour", (_req, res) => res.sendFile(path.join(__dirname, "..", "site", "index.html")));
app.get("/teachers", (_req, res) => res.sendFile(path.join(__dirname, "..", "site", "index.html")));
app.use(
  express.static(path.join(__dirname, "..", "site"), {
    index: "index.html",
    maxAge: process.env.NODE_ENV === "production" ? "1h" : 0,
  }),
);
app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "..", "site", "home.html")));
app.use("/api", (_req, res) => res.status(404).json({ error: "مسیر API پیدا نشد." }));

app.use((err, _req, res, next) => {
  if (res.headersSent) return next(err);
  const status = err?.type === "entity.parse.failed" ? 400 : 500;
  console.error("Request failed:", err?.message || err);
  res.status(status).json({
    error: status === 400 ? "بدنه درخواست معتبر نیست." : "خطای داخلی سرور.",
  });
});

// ---------------------------------------------------------------------------
// Startup + migration
// ---------------------------------------------------------------------------

async function normalizeLegacySequences() {
  const collection = SyncChange.collection;
  const docs = await collection.find({}).sort({ createdAt: 1, _id: 1 }).toArray();
  const seen = new Set();
  let max = 0;
  for (const doc of docs) {
    if (Number.isSafeInteger(doc.seq) && doc.seq > 0) max = Math.max(max, doc.seq);
  }
  for (const doc of docs) {
    const valid = Number.isSafeInteger(doc.seq) && doc.seq > 0 && !seen.has(doc.seq);
    if (valid) {
      seen.add(doc.seq);
      continue;
    }
    max += 1;
    seen.add(max);
    await collection.updateOne({ _id: doc._id }, { $set: { seq: max }, $unset: { cursor: "" } });
  }
  return max;
}

async function backfillLegacyData() {
  await Student.updateMany({ deleted: null }, { $set: { deleted: false } });
  await Report.updateMany({ deleted: null }, { $set: { deleted: false } });
  await Student.updateMany({ revision: null }, { $set: { revision: 1 } });
  await Report.updateMany({ revision: null }, { $set: { revision: 1 } });
  await Student.updateMany(
    { serverUpdatedAt: null },
    [{ $set: { serverUpdatedAt: { $ifNull: ["$updatedAt", "$$NOW"] } } }],
  );
  await Report.updateMany(
    { serverUpdatedAt: null },
    [{ $set: { serverUpdatedAt: { $ifNull: ["$updatedAt", "$$NOW"] } } }],
  );
  await Report.updateMany({ reportType: null }, { $set: { reportType: "کارنامه" } });
  await Report.updateMany({ reportType: "" }, { $set: { reportType: "کارنامه" } });

  const flag = await Config.findOne({ key: "schema-v2-migrated" }).lean();
  if (flag?.value?.done) return;

  const seenIdentities = new Set(
    (await Report.find({ identityKey: { $type: "string", $ne: "" } })
      .select("identityKey")
      .lean()).map((item) => item.identityKey),
  );
  const cursor = Report.find({
    $or: [
      { reportKey: "" },
      { reportKey: null },
      { reportKey: { $exists: false } },
      { identityKey: "" },
      { identityKey: null },
      { identityKey: { $exists: false } },
    ],
  }).cursor();
  for await (const report of cursor) {
    const reportKey = reportKeyOf(report.reportType);
    const identityKey = identityKeyOf(report.nationalId, report.academicYear, report.reportType);
    report.reportKey = reportKey;
    if (!seenIdentities.has(identityKey)) {
      report.identityKey = identityKey;
      seenIdentities.add(identityKey);
    } else {
      console.warn(
        `Duplicate report identity left untouched for review: ${report.id} (${identityKey})`,
      );
    }
    await report.save();
  }

  const students = Student.find({
    $or: [
      { classId: "" },
      { classId: null },
      { classId: { $exists: false } },
      { firstName: "" },
      { firstName: null },
      { firstName: { $exists: false } },
      { lastName: "" },
      { lastName: null },
      { lastName: { $exists: false } },
    ],
  }).cursor();
  for await (const student of students) {
    let changed = false;
    if (student.data?.classId && student.classId !== student.data.classId) {
      student.classId = String(student.data.classId);
      changed = true;
    }
    if (student.data?.firstName && student.firstName !== student.data.firstName) {
      student.firstName = String(student.data.firstName);
      changed = true;
    }
    if (student.data?.lastName && student.lastName !== student.data.lastName) {
      student.lastName = String(student.data.lastName);
      changed = true;
    }
    if (changed) await student.save();
  }
  await Config.findOneAndUpdate(
    { key: "schema-v2-migrated" },
    { $set: { value: { done: true, at: new Date() }, updatedAt: new Date() } },
    { upsert: true },
  );
}

async function ensureSyncCounter(maxSequence = 0) {
  const latest = await SyncChange.findOne({ seq: { $type: "number" } })
    .sort({ seq: -1 })
    .select("seq")
    .lean();
  const max = Math.max(maxSequence, latest?.seq || 0);
  await Counter.findOneAndUpdate(
    { key: "sync-seq" },
    { $max: { value: max } },
    { upsert: true, new: true, setDefaultsOnInsert: true },
  );
}

async function start(port = DEFAULT_PORT, host = DEFAULT_HOST) {
  await mongoose.connect(process.env.MONGODB_URI, {
    serverSelectionTimeoutMS: 10000,
    autoIndex: false,
  });
  await ensureInitialAdmin();
  const maxSequence = await normalizeLegacySequences();
  await backfillLegacyData();
  const models = [Teacher, Student, Report, ScoreAudit, AdminAudit, SyncChange, Counter, Config];
  for (const model of models) {
    try {
      await model.createIndexes();
    } catch (error) {
      console.error(`Index build warning for ${model.modelName}:`, error.message);
    }
  }
  await ensureSyncCounter(maxSequence);
  return new Promise((resolve, reject) => {
    const server = app.listen(port, host, () => {
      const address = server.address();
      console.log(`Sampad portal ${APP_VERSION} listening on ${host}:${address.port}`);
      resolve(server);
    });
    server.on("error", reject);
  });
}

if (require.main === module) {
  start().catch((error) => {
    console.error("Server startup failed:", error);
    process.exit(1);
  });
}

module.exports = {
  app,
  start,
  runtimeConfig: { isRender: IS_RENDER, publicOrigin: PUBLIC_ORIGIN, host: DEFAULT_HOST, port: DEFAULT_PORT },
};
