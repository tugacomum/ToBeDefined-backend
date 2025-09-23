import mongoose from "mongoose";
const { Schema, model, Types } = mongoose;
import enums, { requiredMsg } from "./utils/Enums.js";
import {
  SpecMultipleSchema,
  SpecTrueFalseSchema,
  SpecOpenSchema,
  SpecCodeSchema,
} from "./Exercise.js";

const ExerciseRevisionSchema = new Schema(
  {
    exerciseId: {
      type: Types.ObjectId,
      ref: "Exercise",
      required: true,
      index: true,
    },
    version: { type: Number, required: true, min: 1 },
    statement: { type: String, required: [true, requiredMsg("statement")] },
    type: { type: String, enum: enums.exerciseType, required: true }, // spec é polimórfico; guardamos num campo discriminado
    spec_multiple: SpecMultipleSchema,
    spec_true_false: SpecTrueFalseSchema,
    spec_open: SpecOpenSchema,
    spec_code: SpecCodeSchema, // validação simples para garantir que a spec certa existe
  },
  { timestamps: true, collection: "exercise_revisions" }
);

ExerciseRevisionSchema.index({ exerciseId: 1, version: 1 }, { unique: true });

ExerciseRevisionSchema.pre("validate", function (next) {
  const t = this.type;
  const ok =
    (t === "multiple" &&
      this.spec_multiple &&
      this.spec_multiple.options?.length >= 2) ||
    (t === "true_false" &&
      this.spec_true_false &&
      typeof this.spec_true_false.answer === "boolean") ||
    (t === "open" && this.spec_open) ||
    (t === "code" && this.spec_code && this.spec_code.language);
  if (!ok) return next(new Error("Spec incompatível com o tipo de exercício."));
  next();
});

export default model("ExerciseRevision", ExerciseRevisionSchema);
