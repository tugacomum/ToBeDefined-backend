import mongoose from "mongoose";
const { Schema, model, Types } = mongoose;
const schema = new Schema(
  {
    course: {
      type: Types.ObjectId,
      ref: "Course",
      required: true,
      index: true,
    },
    topic: { type: String, required: true },
    statement: { type: String, required: true },
    isTrue: { type: Boolean, required: true },
    explanation: { type: String, default: "" },
    difficulty: {
      type: String,
      enum: ["easy", "medium", "hard"],
      default: "easy",
    },
  },
  { timestamps: true }
);
export default model("ExerciseTrueFalse", schema);
