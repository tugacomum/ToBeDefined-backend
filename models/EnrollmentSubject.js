import mongoose from "mongoose";
const { Schema, model, Types } = mongoose;
import enums from "./utils/Enums.js";

const EnrollmentSubjectSchema = new Schema(
  {
    userId: { type: Types.ObjectId, ref: "User", required: true, index: true },
    subjectId: {
      type: Types.ObjectId,
      ref: "Subject",
      required: true,
      index: true,
    },
    status: { type: String, enum: enums.enrollmentStatus, default: "active" },
    progress: {
      percent: { type: Number, default: 0, min: 0, max: 1 },
      lastModuleId: { type: Types.ObjectId, ref: "Module" },
      lastAccessAt: { type: Date },
    },
    grades: {
      exercises: { type: Number },
      final: { type: Number },
    },
  },
  { timestamps: true, collection: "enrollments_subject" }
);
EnrollmentSubjectSchema.index({ userId: 1, subjectId: 1 }, { unique: true });

export default model("EnrollmentSubject", EnrollmentSubjectSchema);
