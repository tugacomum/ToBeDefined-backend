import mongoose from "mongoose";
const { Schema, model, Types } = mongoose;

const CodeTestSchema = new Schema(
  {
    kind: { type: String, enum: ["io", "unit"], default: "unit" },
    input: { type: String, default: "" }, // JSON com args no modo "unit", texto no modo "io"
    expectedOutput: { type: String, default: "" }, // comparação textual no MVP
    public: { type: Boolean, default: true },
    weight: { type: Number, default: 1 },
  },
  { _id: false }
);

const ExerciseCodeSchema = new Schema(
  {
    course: {
      type: Types.ObjectId,
      ref: "Course",
      required: true,
      index: true,
    },
    topic: { type: String, required: true },
    title: { type: String, required: true },
    prompt: { type: String, required: true },
    language: { type: String, enum: ["javascript"], required: true },
    starterCode: { type: String, default: "" },
    functionName: { type: String, default: "" },
    timeLimitMs: { type: Number, default: 2000 },
    memoryLimitMb: { type: Number, default: 128 },
    tests: { type: [CodeTestSchema], default: [] },
    difficulty: {
      type: String,
      enum: ["easy", "medium", "hard"],
      default: "easy",
    },
  },
  { timestamps: true }
);

export default model("ExerciseCode", ExerciseCodeSchema);
