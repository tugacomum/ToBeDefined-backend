import mongoose from "mongoose";
const { Schema, model, Types } = mongoose;
const CourseSchema = new Schema(
  {
    title: { type: String, required: true, trim: true },
    description: { type: String, default: "" },
    level: {
      type: String,
      enum: ["intro", "intermediate", "advanced"],
      default: "intro",
    },
    instructor: { type: Types.ObjectId, ref: "User" },
    slug: { type: String, required: true, unique: true, lowercase: true },
  },
  { timestamps: true }
);
export default model("Course", CourseSchema);
