import mongoose, { Schema, Types, model } from "mongoose";

const CodeRunSchema = new Schema(
  {
    userId: { type: Types.ObjectId, ref: "User", required: true, index: true },
    exerciseId: {
      type: Types.ObjectId,
      ref: "Exercise",
      required: true,
      index: true,
    },
    language: { type: String, required: true },
    source: { type: String, required: true },
    stdout: { type: String, default: "" },
    stderr: { type: String, default: "" },
    cpuMs: { type: Number },
    memKb: { type: Number },
    status: { type: String, enum: ["ok", "error", "timeout"], default: "ok" },
    ranAt: { type: Date, default: Date.now },
  },
  { timestamps: true, collection: "code_runs" }
);

export default model("CodeRun", CodeRunSchema);
