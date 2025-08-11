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
    prompt: { type: String, required: true },
    sampleAnswer: { type: String, default: "" },
    maxScore: { type: Number, default: 1 },
  },
  { timestamps: true }
);
export default model("ExerciseOpenEnded", schema);
