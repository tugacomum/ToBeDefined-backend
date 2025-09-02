import mongoose from "mongoose";
const { Schema, model, Types } = mongoose;

const CourseSchema = new Schema(
  {
    title: { type: String, required: true, trim: true },
    description: { type: String, default: "" },
    type: {
      type: String,
      enum: ["ctesp", "licenciatura", "mestrado", "doutoramento"],
      required: true
    },
    instructor: { type: Types.ObjectId, ref: "User" },
  },
  { timestamps: true }
);

export default model("Course", CourseSchema);
