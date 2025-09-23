import mongoose from "mongoose";
const { Schema, model, Types } = mongoose;
import { requiredMsg } from "./utils/Enums.js";

const SubjectSchema = new Schema(
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
    description: String,
    moduleIds: [{ type: Types.ObjectId, ref: "Module", index: true }],
    isActive: { type: Boolean, default: true },
  },
  { timestamps: true, collection: "subjects" }
);
export default model("Subject", SubjectSchema);
