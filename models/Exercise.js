import mongoose from "mongoose";
const { Schema, model, Types } = mongoose;
import enums, { requiredMsg } from "./utils/Enums.js";

const SpecMultipleSchema = new Schema(
  {
    options: {
      type: [String],
      validate: (v) => Array.isArray(v) && v.length >= 2,
    },
    answers: {
      type: [String],
      validate: (v) => Array.isArray(v) && v.length >= 1,
    },
    shuffle: { type: Boolean, default: true },
  },
  { _id: false }
);

const SpecTrueFalseSchema = new Schema(
  {
    answer: { type: Boolean, required: true },
  },
  { _id: false }
);

const SpecOpenSchema = new Schema(
  {
    rubric: { type: [String], default: [] },
    maxChars: { type: Number, default: 1000 },
    keywords: { type: [String], default: [] }, // opcional para apoio à auto-avaliação
  },
  { _id: false }
);

// Teste de código: IO (stdin/stdout) ou Unit (função + args)
const CodeTestIOSchema = new Schema(
  {
    kind: { type: String, enum: ["io"], default: "io" },
    stdin: { type: String, default: "" }, // em vez de "input"
    expectedOutput: { type: String, default: "" },
    compare: {
      type: String,
      enum: ["exact", "trimmed", "regex", "tokens", "numericTolerance"],
      default: "trimmed",
    },
    tolerance: { type: Number, default: 0 }, // usado se compare === 'numericTolerance'
    public: { type: Boolean, default: true },
    weight: { type: Number, default: 1, min: 0 },
  },
  { _id: false }
);

const CodeTestUnitSchema = new Schema(
  {
    kind: { type: String, enum: ["unit"], default: "unit" },
    functionName: { type: String, required: true }, // nome da função a invocar no runner
    args: { type: [Schema.Types.Mixed], default: [] }, // argumentos tipados (array), não JSON string
    expected: Schema.Types.Mixed, // valor esperado (número, string, objeto…)
    compare: {
      type: String,
      enum: ["deepEqual", "regex", "numericTolerance"],
      default: "deepEqual",
    },
    tolerance: { type: Number, default: 0 },
    public: { type: Boolean, default: true },
    weight: { type: Number, default: 1, min: 0 },
  },
  { _id: false }
);

const CodeTestSchema = new Schema(
  {
    kind: { type: String, enum: ["io", "unit"], required: true },
    // Campos “union”: manter todos opcionais e validar no pre('validate')
    stdin: String,
    expectedOutput: String,
    functionName: String,
    args: { type: [Schema.Types.Mixed], default: undefined },
    expected: Schema.Types.Mixed,
    compare: {
      type: String,
      enum: [
        "exact",
        "trimmed",
        "regex",
        "tokens",
        "numericTolerance",
        "deepEqual",
      ],
      default: "trimmed",
    },
    tolerance: { type: Number, default: 0 },
    public: { type: Boolean, default: true },
    weight: { type: Number, default: 1, min: 0 },
  },
  { _id: false }
);

CodeTestSchema.pre("validate", function (next) {
  const k = this.kind;
  if (k === "io") {
    if (typeof this.expectedOutput !== "string")
      return next(
        new Error("expectedOutput (string) é obrigatório em testes IO.")
      );
  }
  if (k === "unit") {
    if (!this.functionName)
      return next(new Error("functionName é obrigatório em testes Unit."));
  }
  next();
});

const SpecCodeSchema = new Schema(
  {
    language: { type: String, required: true }, // 'python', 'sql', ...
    timeoutSec: { type: Number, default: 5 },
    memoryMb: { type: Number, default: 256 },
    // Ambiente de execução opcional
    runtime: { type: String, default: "default" }, // p.ex. 'python3.11-sandbox'
    setup: { type: String, default: "" }, // código de setup (opcional)
    teardown: { type: String, default: "" },
    tests: { type: [CodeTestSchema], default: [] },
  },
  { _id: false }
);

const ExerciseSchema = new Schema(
  {
    subjectId: {
      type: Types.ObjectId,
      ref: "Subject",
      required: true,
      index: true,
    },
    moduleId: {
      type: Types.ObjectId,
      ref: "Module",
      required: true,
      index: true,
    },
    title: { type: String, required: [true, requiredMsg("title")] },
    type: {
      type: String,
      enum: enums.exerciseType,
      required: true,
      index: true,
    },
    difficulty: {
      type: String,
      enum: ["easy", "medium", "hard"],
      default: "easy",
    },
    points: { type: Number, default: 1, min: 0 },
    tags: { type: [String], default: [] },
    currentVersion: { type: Number, default: 1, min: 1 },
    active: { type: Boolean, default: true },
  },
  { timestamps: true, collection: "exercises" }
);

export default model("Exercise", ExerciseSchema);
export {
  SpecMultipleSchema,
  SpecTrueFalseSchema,
  SpecOpenSchema,
  SpecCodeSchema,
};
