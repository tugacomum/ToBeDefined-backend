import mongoose from "mongoose";
export async function connectDB() {
  const uri = process.env.MONGODB_URI;
  mongoose.set("strictQuery", true);
  await mongoose.connect(uri);
  console.log("MongoDB connected");
}
