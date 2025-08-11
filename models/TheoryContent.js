import mongoose from "mongoose";
const { Schema, model, Types } = mongoose;
const TheoryContentSchema = new Schema(
  {
    course: {
      type: Types.ObjectId,
      ref: "Course",
      required: true,
      index: true,
    },
    topic: { type: String, required: true },
    title: { type: String, required: true },
    body: { type: String, required: true }, // Markdown
  },
  { timestamps: true }
);
export default model("TheoryContent", TheoryContentSchema);
