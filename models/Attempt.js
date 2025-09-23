import mongoose, { Schema, Types } from "mongoose";
import enums from "./utils/Enums.js";

const RespMultipleSchema = new Schema(
  {
    selected: { type: [String], default: [] },
  },
  { _id: false }
);

const RespTrueFalseSchema = new Schema(
  {
    value: { type: Boolean },
  },
  { _id: false }
);

const RespOpenSchema = new Schema(
  {
    text: { type: String, default: "" },
  },
  { _id: false }
);

const RespCodeSchema = new Schema(
  {
    source: { type: String, default: "" },
    codeRunIds: [{ type: Types.ObjectId, ref: "CodeRun" }],
  },
  { _id: false }
);

const AttemptSchema = new Schema(
  {
    userId: { type: Types.ObjectId, ref: "User", required: true, index: true },
    subjectId: {
      type: Types.ObjectId,
      ref: "Subject",
      required: true,
      index: true,
    },
    exerciseId: {
      type: Types.ObjectId,
      ref: "Exercise",
      required: true,
      index: true,
    },
    revisionId: {
      type: Types.ObjectId,
      ref: "ExerciseRevision",
      required: true,
      index: true,
    },
    status: { type: String, enum: enums.attemptStatus, default: "submitted" },
    submittedAt: { type: Date, default: Date.now },
    response: {
      multiple: RespMultipleSchema,
      true_false: RespTrueFalseSchema,
      open: RespOpenSchema,
      code: RespCodeSchema,
    },
    autoScore: { type: Number, default: 0 },
    manualScore: { type: Number, default: 0 },
    totalScore: { type: Number, default: 0 },
    feedback: { type: String },
  },
  { timestamps: true, collection: "attempts" }
);
AttemptSchema.index({ exerciseId: 1, userId: 1, submittedAt: -1 });

export default mongoose.model("Attempt", AttemptSchema);
export {
  RespMultipleSchema,
  RespTrueFalseSchema,
  RespOpenSchema,
  RespCodeSchema,
};
