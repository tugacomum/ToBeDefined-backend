import mongoose from "mongoose";
import enums, { requiredMsg } from "./utils/Enums.js";
const { Schema, model, Types } = mongoose;

const CourseSchema = new Schema(
  {
    title: { type: String, required: [true, requiredMsg("title")] },
    slug: {
      type: String,
      trim: true,
      lowercase: true,
      unique: true,
      sparse: true,
      index: true,
    },
    description: { type: String, default: "" },
    type: {
      type: String,
      enum: enums.courseType,
      required: true,
    },
    subjectIds: [{ type: Types.ObjectId, ref: "Subject", index: true }],
    isActive: { type: Boolean, default: true },
  },
  { timestamps: true }
);

export default model("Course", CourseSchema);
