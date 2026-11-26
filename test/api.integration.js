const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { MongoMemoryServer } = require("mongodb-memory-server");

process.env.NODE_ENV = "test";
process.env.JWT_SECRET = "test-secret-".padEnd(80, "x");
process.env.COOKIE_SECURE = "false";
process.env.PUBLIC_ORIGIN = "";
process.env.FORCE_HTTPS = "";
process.env.LOG_LEVEL = "error";

const argon2 = require("argon2");

let mongod;
let server;
let base;
let adminCookie;
let teacherCookie;
let teacherId;
let mongoDbPath;

async function request(path, { method = "GET", body, cookie, origin, raw = false } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (cookie) headers.Cookie = cookie;
  if (origin) headers.Origin = origin;
  const response = await fetch(`${base}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const setCookie = response.headers.getSetCookie?.() || [];
  const text = await response.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  return { response, data, setCookie, raw };
}

function sessionCookie(setCookie) {
  const pair = setCookie.find((value) => value.startsWith("sampad_session="));
  assert.ok(pair, "session cookie must be issued");
  return pair.split(";")[0];
}

async function main() {
  console.log("Starting in-memory MongoDB…");
  // The Codex/Windows sandbox denies MongoDB WiredTiger rename operations in
  // the OS temp directory. Keep the disposable test database inside workspace.
  mongoDbPath = fs.mkdtempSync(path.join(__dirname, ".mongo-test-"));
  mongod = await MongoMemoryServer.create({ instance: { dbPath: mongoDbPath } });
  process.env.MONGODB_URI = mongod.getUri("sampad-test");
  const { start } = require("../api/server");
  server = await start(0, "127.0.0.1");
  base = `http://127.0.0.1:${server.address().port}`;
  const models = require("../api/models");

  for (const route of ["/", "/tour", "/app.css", "/app.js"]) {
    const page = await fetch(`${base}${route}`);
    assert.equal(page.status, 200, `website resource ${route} should load`);
    assert.ok(page.headers.get("content-security-policy"), "security headers must be present");
  }
  const landing = await fetch(base);
  assert.match(await landing.text(), /کد امنیتی مدرسه/);

  const password = "AdminPassword123!";
  const admin = await models.Teacher.create({
    firstName: "مدیر",
    lastName: "آزمون",
    nationalId: "0012345678",
    phone: "09120000000",
    passwordHash: await argon2.hash(password, { type: argon2.argon2id }),
    role: "admin",
    active: true,
    assignments: [],
  });

  let result = await request("/api/login", {
    method: "POST",
    body: { nationalId: "0012345678", password },
  });
  assert.equal(result.response.status, 200);
  adminCookie = sessionCookie(result.setCookie);

  const classes = [
    { id: "c10m", label: "دهم ریاضی", grade: "10", field: "ریاضی" },
    { id: "c11e1", label: "یازدهم تجربی ۱", grade: "11", field: "تجربی" },
  ];
  const subjects = [
    { id: "math1", name: "ریاضی (۱)", grade: "10", field: "ریاضی", coefficient: 2 },
    { id: "phys1", name: "فیزیک (۱)", grade: "10", field: "ریاضی", coefficient: 1 },
    { id: "bio2", name: "زیست‌شناسی (۲)", grade: "11", field: "تجربی", coefficient: 3 },
  ];
  result = await request("/api/admin/bootstrap", {
    method: "PUT",
    cookie: adminCookie,
    body: { securityCode: "123456", classes, subjects, archivedYears: [] },
  });
  assert.equal(result.response.status, 200, JSON.stringify(result.data));
  assert.equal(result.data.hasSecurityCode, true);

  result = await request("/api/bootstrap/verify", {
    method: "POST",
    body: { securityCode: "654321" },
  });
  assert.equal(result.response.status, 403);
  result = await request("/api/bootstrap/verify", {
    method: "POST",
    body: { securityCode: "123456" },
  });
  assert.equal(result.response.status, 200);
  assert.equal(result.data.classes.length, 2);

  result = await request("/api/register", {
    method: "POST",
    body: {
      firstName: "معلم",
      lastName: "یک",
      nationalId: "1122334455",
      phone: "09121111111",
      password: "TeacherPassword123!",
      securityCode: "123456",
      assignments: [{ classId: "c10m", subjectId: "math1", subjectName: "ریاضی (۱)" }],
    },
  });
  assert.equal(result.response.status, 201, JSON.stringify(result.data));
  teacherCookie = sessionCookie(result.setCookie);
  teacherId = result.data.user.id;

  result = await request("/api/register", {
    method: "POST",
    body: {
      firstName: "تکراری",
      lastName: "تکراری",
      nationalId: "1122334455",
      phone: "09121111111",
      password: "TeacherPassword123!",
      securityCode: "123456",
      assignments: [{ classId: "c10m", subjectId: "math1", subjectName: "ریاضی (۱)" }],
    },
  });
  assert.equal(result.response.status, 409);

  result = await request("/api/me", { cookie: teacherCookie });
  assert.equal(result.response.status, 200);
  assert.equal(result.data.user.role, "teacher");

  result = await request("/api/me", {
    cookie: teacherCookie,
    method: "PATCH",
    body: { firstName: "معلم", lastName: "ویرایش‌شده", phone: "09122222222" },
  });
  assert.equal(result.response.status, 200);
  assert.equal(result.data.user.lastName, "ویرایش‌شده");

  result = await request("/api/admin/teachers", { cookie: teacherCookie });
  assert.equal(result.response.status, 403);

  const studentA = {
    nationalId: "2233445566",
    classId: "c10m",
    firstName: "دانش‌آموز",
    lastName: "الف",
    updatedAt: "2026-01-01T08:00:00.000Z",
  };
  const studentB = {
    nationalId: "3344556677",
    classId: "c10m",
    firstName: "دانش‌آموز",
    lastName: "ب",
    updatedAt: "2026-01-01T08:00:00.000Z",
  };
  const reportA = {
    id: "report-a",
    nationalId: "2233445566",
    classId: "c10m",
    firstName: "دانش‌آموز",
    lastName: "الف",
    academicYear: "1404-1405",
    reportType: "میان‌ترم",
    scores: { math1: 15, phys1: 12 },
    subjectSnapshot: [
      { id: "math1", name: "ریاضی (۱)", coefficient: 2 },
      { id: "phys1", name: "فیزیک (۱)", coefficient: 1 },
    ],
    totalScore: 14,
    updatedAt: "2026-01-02T08:00:00.000Z",
  };
  result = await request("/api/admin/sync", {
    method: "POST",
    cookie: adminCookie,
    body: {
      protocol: 2,
      students: [studentA, studentB],
      reports: [reportA],
      classes,
      subjects,
      settings: { schoolName: "شهید بهشتی تیزهوشان (دوره دوم)", siteSessionCookie: "must-not-sync" },
      archivedYears: [],
      tombstones: { students: [], reports: [] },
    },
  });
  assert.equal(result.response.status, 200, JSON.stringify(result.data));
  assert.equal(result.data.conflicts.length, 0);
  assert.ok(result.data.cursor > 0);

  result = await request("/api/teacher/roster?classId=c10m", { cookie: teacherCookie });
  assert.equal(result.response.status, 200);
  assert.equal(result.data.students.length, 2);
  result = await request("/api/teacher/roster?classId=c11e1", { cookie: teacherCookie });
  assert.equal(result.response.status, 403);

  result = await request(
    "/api/teacher/reports?classId=c10m&academicYear=1404-1405&reportType=%D9%85%DB%8C%D8%A7%D9%86%E2%80%8C%D8%AA%D8%B1%D9%85",
    { cookie: teacherCookie },
  );
  assert.equal(result.response.status, 200, JSON.stringify(result.data));
  assert.equal(result.data.reports.length, 1);
  assert.equal(result.data.reports[0].scores.phys1, undefined, "unauthorized subject must be hidden");
  const reportRevision = result.data.reports[0].revision;

  result = await request("/api/teacher/reports/report-a", {
    method: "PUT",
    cookie: teacherCookie,
    body: {
      ...reportA,
      revision: reportRevision,
      scores: { math1: 17 },
    },
  });
  assert.equal(result.response.status, 200, JSON.stringify(result.data));
  assert.equal(result.data.report.scores.math1, 17);
  assert.equal(result.data.report.scores.phys1, undefined, "other subjects stay hidden from this teacher");
  const revision2 = result.data.revision;
  assert.equal(revision2, reportRevision + 1);

  result = await request("/api/teacher/reports/report-a", {
    method: "PUT",
    cookie: teacherCookie,
    body: { ...reportA, revision: reportRevision, scores: { math1: 8 } },
  });
  assert.equal(result.response.status, 409, JSON.stringify(result.data));
  assert.ok(result.data.current);

  result = await request("/api/teacher/reports/report-a", {
    method: "PUT",
    cookie: teacherCookie,
    body: {
      ...reportA,
      revision: revision2,
      scores: { math1: 17, phys1: 12, bio2: 20 },
    },
  });
  assert.equal(result.response.status, 403);

  result = await request("/api/teacher/reports/report-a", {
    method: "PUT",
    cookie: teacherCookie,
    body: { ...reportA, revision: revision2, scores: { math1: null } },
  });
  assert.equal(result.response.status, 200, JSON.stringify(result.data));
  assert.equal(result.data.report.scores.math1, undefined);
  assert.equal(result.data.report.scores.phys1, undefined);
  const revision3 = result.data.revision;

  result = await request("/api/admin/audit?limit=50", { cookie: adminCookie });
  assert.equal(result.response.status, 200);
  assert.ok(result.data.items.some((item) => item.result === "rejected" && item.reason === "revision_conflict"));
  assert.ok(result.data.items.some((item) => item.result === "saved" && item.action === "cleared"));
  assert.ok(result.data.items.every((item) => item.oldValue !== undefined && item.newValue !== undefined));

  result = await request("/api/admin/students?q=2233445566", { cookie: adminCookie });
  assert.equal(result.response.status, 200);
  assert.equal(result.data.students.length, 1);
  assert.equal(result.data.students[0].reportCount, 1);

  result = await request("/api/admin/students?q=دانش", { cookie: adminCookie });
  assert.equal(result.response.status, 200);
  assert.equal(result.data.students.length, 2);

  const reportB = {
    ...reportA,
    id: "report-b",
    academicYear: "1404-1405",
    reportType: "پایانی",
    scores: { math1: 10 },
    subjectSnapshot: [{ id: "math1", name: "ریاضی (۱)", coefficient: 2 }],
    totalScore: 10,
    updatedAt: "2026-01-03T08:00:00.000Z",
  };
  result = await request("/api/admin/sync", {
    method: "POST",
    cookie: adminCookie,
    body: { protocol: 2, reports: [reportB], students: [], tombstones: {} },
  });
  assert.equal(result.response.status, 200, JSON.stringify(result.data));

  result = await request("/api/admin/students/2233445566/analytics", { cookie: adminCookie });
  assert.equal(result.response.status, 200);
  assert.ok(result.data.topics.includes("میان‌ترم"));
  assert.ok(result.data.topics.includes("پایانی"));
  assert.equal(result.data.subjects.length, 0);
  result = await request(
    "/api/admin/students/2233445566/analytics?reportType=%D9%85%DB%8C%D8%A7%D9%86%E2%80%8C%D8%AA%D8%B1%D9%85",
    { cookie: adminCookie },
  );
  assert.equal(result.response.status, 200);
  assert.equal(result.data.reports.length, 1);
  assert.equal(result.data.reports[0].reportType, "میان‌ترم");
  assert.ok(result.data.subjects.some((item) => item.id === "phys1"));
  assert.ok(result.data.subjects.every((item) => item.id !== "bio2"));

  result = await request("/api/admin/snapshot?type=students&page=1&limit=1", { cookie: adminCookie });
  assert.equal(result.response.status, 200);
  assert.equal(result.data.items.length, 1);
  assert.equal(result.data.hasMore, true);
  result = await request("/api/admin/snapshot?type=meta", { cookie: adminCookie });
  assert.equal(result.response.status, 200);
  assert.ok(result.data.cursor > 0);
  assert.equal(result.data.settings.siteSessionCookie, undefined, "browser session must never sync");

  result = await request("/api/admin/changes?since=0&limit=2", { cookie: adminCookie });
  assert.equal(result.response.status, 200);
  assert.equal(result.data.changes.length, 2);
  assert.equal(result.data.hasMore, true);
  const firstCursor = result.data.cursor;

  result = await request(`/api/admin/changes?since=${firstCursor}&limit=200`, { cookie: adminCookie });
  assert.equal(result.response.status, 200);
  assert.ok(result.data.cursor >= firstCursor);

  // Teacher password change invalidates the old session.
  result = await request("/api/me/password", {
    method: "POST",
    cookie: teacherCookie,
    body: { currentPassword: "TeacherPassword123!", newPassword: "TeacherPassword456!" },
  });
  assert.equal(result.response.status, 200, JSON.stringify(result.data));
  const newTeacherCookie = sessionCookie(result.setCookie);
  result = await request("/api/me", { cookie: teacherCookie });
  assert.equal(result.response.status, 401);
  result = await request("/api/me", { cookie: newTeacherCookie });
  assert.equal(result.response.status, 200);
  teacherCookie = newTeacherCookie;

  // Concurrent teacher update and desktop push must not silently overwrite.
  result = await request("/api/teacher/reports/report-a", {
    method: "PUT",
    cookie: teacherCookie,
    body: { ...reportA, revision: revision3, scores: { math1: 16 } },
  });
  assert.equal(result.response.status, 200, JSON.stringify(result.data));
  const serverRevision = result.data.revision;
  result = await request("/api/admin/sync", {
    method: "POST",
    cookie: adminCookie,
    body: {
      protocol: 2,
      students: [],
      reports: [{ ...reportA, siteRevision: revision3, scores: { math1: 4 } }],
      tombstones: {},
    },
  });
  assert.equal(result.response.status, 200);
  assert.equal(result.data.conflicts.length, 1);
  assert.equal(result.data.conflicts[0].reason, "revision_conflict");
  assert.equal(result.data.conflicts[0].remote.revision, serverRevision);

  result = await request("/api/admin/sync", {
    method: "POST",
    cookie: adminCookie,
    body: {
      protocol: 2,
      students: [],
      reports: [{ ...reportA, siteRevision: revision3, scores: { phys1: 4 } }],
      tombstones: {},
      force: { students: [], reports: ["report-a"] },
    },
  });
  assert.equal(result.response.status, 200);
  assert.equal(result.data.conflicts.length, 0);
  assert.ok(result.data.accepted.some((item) => item.type === "report" && item.revision > serverRevision));

  // Teacher deletion reaches the admin change feed as a tombstone.
  result = await request("/api/teacher/reports/report-a", {
    method: "DELETE",
    cookie: teacherCookie,
  });
  assert.equal(result.response.status, 200, JSON.stringify(result.data));
  result = await request("/api/admin/changes?since=0&limit=500", { cookie: adminCookie });
  assert.equal(result.response.status, 200);
  assert.ok(
    result.data.changes.some(
      (item) => item.type === "report" && item.operation === "delete" && item.entityId === "report-a",
    ),
  );
  result = await request(
    "/api/teacher/reports?classId=c10m&academicYear=1404-1405&reportType=%D9%85%DB%8C%D8%A7%D9%86%E2%80%8C%D8%AA%D8%B1%D9%85",
    { cookie: teacherCookie },
  );
  assert.equal(result.response.status, 200);
  assert.equal(result.data.reports.length, 0);

  // Deleted report cannot be recreated silently by a teacher.
  result = await request("/api/teacher/reports/report-a", {
    method: "PUT",
    cookie: teacherCookie,
    body: { ...reportA, revision: 0, scores: { math1: 20 } },
  });
  assert.equal(result.response.status, 409);

  // Admin deletion reaches teachers and cannot be resurrected by an old local copy.
  result = await request("/api/admin/sync", {
    method: "POST",
    cookie: adminCookie,
    body: {
      protocol: 2,
      students: [studentA],
      reports: [],
      tombstones: {
        students: [{ nationalId: "2233445566", deletedAt: "2026-02-01T00:00:00.000Z" }],
        reports: [],
      },
    },
  });
  assert.equal(result.response.status, 200, JSON.stringify(result.data));
  result = await request("/api/teacher/roster?classId=c10m", { cookie: teacherCookie });
  assert.equal(result.response.status, 200);
  assert.equal(result.data.students.length, 1);
  assert.equal(result.data.students[0].nationalId, "3344556677");

  result = await request("/api/admin/sync", {
    method: "POST",
    cookie: adminCookie,
    body: {
      protocol: 2,
      students: [{ ...studentA, updatedAt: "2026-01-20T00:00:00.000Z" }],
      reports: [],
      tombstones: {},
    },
  });
  assert.equal(result.response.status, 200);
  assert.equal(result.data.conflicts.length, 1);
  assert.equal(result.data.conflicts[0].reason, "deleted_remote");

  // Validation and cross-origin checks.
  const reportC = {
    ...reportB,
    id: "report-c",
    nationalId: "3344556677",
    firstName: "دانش‌آموز",
    lastName: "ب",
    reportType: "آزمون سوم",
    updatedAt: "2026-01-04T08:00:00.000Z",
  };
  result = await request("/api/admin/sync", {
    method: "POST",
    cookie: adminCookie,
    body: { protocol: 2, reports: [reportC], students: [], tombstones: {} },
  });
  assert.equal(result.response.status, 200, JSON.stringify(result.data));
  result = await request(
    "/api/teacher/reports?classId=c10m&academicYear=1404-1405&reportType=%D8%A2%D8%B2%D9%85%D9%88%D9%86%20%D8%B3%D9%88%D9%85",
    { cookie: teacherCookie },
  );
  assert.equal(result.response.status, 200, JSON.stringify(result.data));
  assert.equal(result.data.reports.length, 1);
  const reportCRevision = result.data.reports[0].revision;
  result = await request("/api/teacher/reports/report-c", {
    method: "PUT",
    cookie: teacherCookie,
    body: { ...reportC, revision: reportCRevision, scores: { math1: 25 } },
  });
  assert.equal(result.response.status, 400);

  result = await request("/api/admin/overview", { cookie: adminCookie });
  assert.equal(result.response.status, 200);
  assert.equal(result.data.studentCount, 1);
  assert.equal(result.data.teacherCount, 1);

  result = await request("/api/admin/audit?type=admin&limit=100", { cookie: adminCookie });
  assert.equal(result.response.status, 200);
  assert.ok(result.data.adminItems.some((item) => item.action === "catalog_updated"));
  assert.ok(result.data.adminItems.some((item) => item.action === "password_changed"));

  process.env.PUBLIC_ORIGIN = "https://teachers.example.com";
  result = await request("/api/health", { origin: "https://evil.example.com" });
  assert.equal(result.response.status, 403);
  process.env.PUBLIC_ORIGIN = "";

  process.env.FORCE_HTTPS = "true";
  result = await request("/api/health");
  assert.equal(result.response.status, 403);
  process.env.FORCE_HTTPS = "";

  // Login rate limit (failed attempts).
  for (let index = 0; index < 9; index += 1) {
    result = await request("/api/login", {
      method: "POST",
      body: { nationalId: "0012345678", password: "wrong-password" },
    });
  }
  assert.equal(result.response.status, 429);

  console.log("API integration checks passed.");
  await new Promise((resolve) => server.close(resolve));
  const mongoose = require("mongoose");
  await mongoose.disconnect();
  await mongod.stop();
    if (mongoDbPath) fs.rmSync(mongoDbPath, { recursive: true, force: true });
}

main().catch(async (error) => {
  console.error(error);
  try {
    if (server) await new Promise((resolve) => server.close(resolve));
    const mongoose = require("mongoose");
    await mongoose.disconnect();
    if (mongod) await mongod.stop();
    if (mongoDbPath) fs.rmSync(mongoDbPath, { recursive: true, force: true });
  } catch {}
  process.exit(1);
});
