import { Schema, model, Types } from "mongoose";
import { requiredMsg } from "./utils/Enums.js";

const ContentBlockSchema = new Schema(
  {
    type: {
      type: String,
      enum: ["text", "image", "video", "html", "link"],
      required: true,
    },
    data: { type: Schema.Types.Mixed },
    assetId: { type: Types.ObjectId, ref: "Asset" },
    caption: String,
  },
  { _id: false }
);

const ModuleSchema = new Schema(
  {
    subjectId: {
      type: Types.ObjectId,
      ref: "Subject",
      required: true,
      index: true,
    },
    title: { type: String, required: [true, requiredMsg("title")] },
    order: { type: Number, default: 0, index: true },
    theory: { blocks: { type: [ContentBlockSchema], default: [] } },
    exerciseIds: [{ type: Types.ObjectId, ref: "Exercise", index: true }],
  },
  { timestamps: true, collection: "modules" }
);
ModuleSchema.index({ subjectId: 1, order: 1 });

export default model("Module", ModuleSchema);
