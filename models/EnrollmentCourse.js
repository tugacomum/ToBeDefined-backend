import mongoose, { Schema, Types } from "mongoose";

const EnrollmentCourseSchema = new Schema(
  {
    userId: { type: Types.ObjectId, ref: "User", required: true, index: true },
    courseId: {
      type: Types.ObjectId,
      ref: "Course",
      required: true,
      index: true,
    },
    progress: {
      subjectsCompleted: { type: Number, default: 0 },
      subjectsTotal: { type: Number, default: 0 },
    },
  },
  { timestamps: true, collection: "enrollments_course" }
);
EnrollmentCourseSchema.index({ userId: 1, courseId: 1 }, { unique: true });

export default mongoose.model("EnrollmentCourse", EnrollmentCourseSchema);
