const mongoose = require("mongoose");
const { Schema } = mongoose;

const assignmentSchema = new Schema(
  {
    classId: { type: String, required: true, trim: true, maxlength: 120 },
    subjectId: { type: String, required: true, trim: true, maxlength: 120 },
    subjectName: { type: String, required: true, trim: true, maxlength: 160 },
    grade: { type: String, default: "" },
    field: { type: String, default: "" },
  },
  { _id: false },
);

const teacherSchema = new Schema(
  {
    firstName: { type: String, required: true, trim: true, maxlength: 80 },
    lastName: { type: String, required: true, trim: true, maxlength: 80 },
    nationalId: {
      type: String,
      required: true,
      unique: true,
      index: true,
      match: /^\d{10}$/,
    },
    phone: { type: String, required: true, trim: true, maxlength: 24 },
    passwordHash: { type: String, required: true, select: false },
    role: { type: String, enum: ["teacher", "admin"], default: "teacher" },
    active: { type: Boolean, default: true },
    tokenVersion: { type: Number, default: 0 },
    lastSeenAt: Date,
    lastLoginAt: Date,
    loginCount: { type: Number, default: 0 },
    assignments: { type: [assignmentSchema], default: [] },
  },
  { timestamps: true, strict: "throw" },
);
teacherSchema.index({ firstName: 1, lastName: 1 });
teacherSchema.index({ role: 1, active: 1 });

const studentSchema = new Schema(
  {
    nationalId: {
      type: String,
      required: true,
      unique: true,
      index: true,
      match: /^\d{10}$/,
    },
    classId: { type: String, default: "", index: true },
    firstName: { type: String, default: "", trim: true, maxlength: 120 },
    lastName: { type: String, default: "", trim: true, maxlength: 120 },
    data: { type: Schema.Types.Mixed, required: true },
    revision: { type: Number, default: 1 },
    updatedAt: { type: Date, default: Date.now },
    serverUpdatedAt: { type: Date, default: Date.now },
    updatedBy: { type: Schema.Types.Mixed, default: null },
    deleted: { type: Boolean, default: false, index: true },
    deletedAt: Date,
    deletedBy: { type: Schema.Types.Mixed, default: null },
  },
  { strict: "throw", minimize: false },
);
studentSchema.index({ classId: 1, lastName: 1, firstName: 1 });
studentSchema.index({ lastName: 1, firstName: 1 });

const reportSchema = new Schema(
  {
    id: { type: String, required: true, unique: true, index: true },
    nationalId: { type: String, required: true, index: true, match: /^\d{10}$/ },
    classId: { type: String, required: true, index: true },
    academicYear: { type: String, required: true, index: true },
    reportType: { type: String, default: "کارنامه" },
    reportKey: { type: String, default: "", index: true },
    identityKey: { type: String, default: "", index: true },
    data: { type: Schema.Types.Mixed, required: true },
    revision: { type: Number, default: 1 },
    updatedAt: { type: Date, default: Date.now },
    serverUpdatedAt: { type: Date, default: Date.now },
    updatedBy: { type: Schema.Types.Mixed, default: null },
    deleted: { type: Boolean, default: false, index: true },
    deletedAt: Date,
    deletedBy: { type: Schema.Types.Mixed, default: null },
  },
  { strict: "throw", minimize: false },
);
reportSchema.index({ classId: 1, academicYear: 1, reportKey: 1 });
reportSchema.index({ nationalId: 1, academicYear: 1, reportKey: 1 });
reportSchema.index(
  { identityKey: 1 },
  {
    unique: true,
    partialFilterExpression: { identityKey: { $gt: "" } },
    name: "uniq_report_identity",
  },
);

const scoreAuditSchema = new Schema(
  {
    reportId: { type: String, required: true, index: true },
    subjectId: { type: String, required: true },
    subjectName: { type: String, default: "" },
    classId: { type: String, default: "" },
    academicYear: { type: String, default: "" },
    reportType: { type: String, default: "" },
    oldValue: { type: Schema.Types.Mixed, default: null },
    newValue: { type: Schema.Types.Mixed, default: null },
    action: {
      type: String,
      enum: ["set", "cleared", "deleted", "rejected"],
      default: "set",
    },
    result: {
      type: String,
      enum: ["saved", "rejected", "failed"],
      default: "saved",
      index: true,
    },
    reason: { type: String, default: "" },
    actorId: { type: Schema.Types.ObjectId, ref: "Teacher", index: true },
    actorName: { type: String, default: "" },
    createdAt: { type: Date, default: Date.now, index: true },
  },
  { strict: "throw" },
);
scoreAuditSchema.index({ actorId: 1, createdAt: -1 });
scoreAuditSchema.index({ result: 1, createdAt: -1 });

const adminAuditSchema = new Schema(
  {
    action: { type: String, required: true },
    targetType: { type: String, required: true },
    targetId: { type: String, default: "" },
    summary: { type: String, default: "" },
    oldValue: { type: Schema.Types.Mixed, default: null },
    newValue: { type: Schema.Types.Mixed, default: null },
    result: {
      type: String,
      enum: ["saved", "rejected", "failed"],
      default: "saved",
      index: true,
    },
    actorId: { type: Schema.Types.ObjectId, ref: "Teacher", index: true },
    actorName: { type: String, default: "" },
    createdAt: { type: Date, default: Date.now, index: true },
  },
  { strict: "throw" },
);
adminAuditSchema.index({ createdAt: -1 });
adminAuditSchema.index({ actorId: 1, createdAt: -1 });

const syncChangeSchema = new Schema(
  {
    seq: { type: Number, required: true, unique: true, index: true },
    entityType: {
      type: String,
      required: true,
      enum: ["student", "report", "meta"],
      index: true,
    },
    entityId: { type: String, required: true },
    operation: {
      type: String,
      required: true,
      enum: ["upsert", "delete"],
      index: true,
    },
    data: { type: Schema.Types.Mixed, default: null },
    revision: { type: Number, default: 0 },
    source: {
      type: String,
      enum: ["desktop", "teacher", "server"],
      default: "server",
      index: true,
    },
    actorId: { type: Schema.Types.ObjectId, ref: "Teacher", default: null },
    actorName: { type: String, default: "" },
    createdAt: { type: Date, default: Date.now, index: true },
  },
  { strict: "throw" },
);
syncChangeSchema.index({ seq: 1, entityType: 1 });

const counterSchema = new Schema(
  {
    key: { type: String, required: true, unique: true },
    value: { type: Number, default: 0 },
  },
  { strict: "throw" },
);

const configSchema = new Schema(
  {
    key: { type: String, required: true, unique: true, index: true },
    value: { type: Schema.Types.Mixed, required: true },
    updatedAt: { type: Date, default: Date.now },
  },
  { strict: "throw", minimize: false },
);

module.exports = {
  Teacher: mongoose.model("Teacher", teacherSchema),
  Student: mongoose.model("Student", studentSchema),
  Report: mongoose.model("Report", reportSchema),
  ScoreAudit: mongoose.model("ScoreAudit", scoreAuditSchema),
  AdminAudit: mongoose.model("AdminAudit", adminAuditSchema),
  SyncChange: mongoose.model("SyncChange", syncChangeSchema),
  Counter: mongoose.model("Counter", counterSchema),
  Config: mongoose.model("Config", configSchema),
};
