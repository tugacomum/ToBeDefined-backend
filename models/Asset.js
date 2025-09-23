import mongoose from "mongoose";
const { Schema, model, Types } = mongoose;

const AssetSchema = new Schema(
  {
    kind: {
      type: String,
      enum: ["video", "image", "pdf", "audio", "other"],
      required: true,
    },
    storage: {
      provider: {
        type: String,
        enum: ["s3", "gcs", "minio", "fs", "other"],
        required: true,
      },
      bucket: { type: String, required: true },
      key: { type: String, required: true },
      url: { type: String }, // opcional: URL assinada / CDN
    },
    meta: {
      durationSec: Number,
      size: Number,
      checksum: String,
      contentType: String,
    },
    ownerId: { type: Types.ObjectId, ref: "User" },
  },
  { timestamps: true, collection: "assets" }
);

export default model("Asset", AssetSchema);
