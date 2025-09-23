import mongoose from "mongoose";
const { Schema, model } = mongoose;
import enums, { requiredMsg } from "./utils/Enums.js";

const UserSchema = new Schema(
  {
    firstName: {
      type: String,
      trim: true,
      required: [true, requiredMsg("firstName")],
    },
    lastName: {
      type: String,
      trim: true,
      required: [true, requiredMsg("lastName")],
    },
    email: {
      type: String,
      trim: true,
      lowercase: true,
      unique: true,
      index: true,
      required: [true, requiredMsg("email")],
    },
    status: {
      type: String,
      enum: ["active", "inactive", "blocked"],
      default: "active",
    },
    passwordHash: { type: String, required: true },
    roles: { type: [String], enum: enums.role, default: ["student"] },
    verificationCode: { type: String },
    verificationCodeExpiresAt: { type: Date },
    isVerified: { type: Boolean, default: false },
    resetPasswordToken: { type: String },
    resetPasswordExpiresAt: { type: Date },
  },
  { timestamps: true, collection: "users" }
);

export default model("User", UserSchema);
