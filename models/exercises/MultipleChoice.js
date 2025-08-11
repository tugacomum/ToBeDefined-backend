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
    question: { type: String, required: true },
    options: [{ type: String, required: true }],
    correctIndexes: [{ type: Number, required: true }],
    explanation: { type: String, default: "" },
    difficulty: {
      type: String,
      enum: ["easy", "medium", "hard"],
      default: "easy",
    },
  },
  { timestamps: true }
);
export default model("ExerciseMultipleChoice", schema);
