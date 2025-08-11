import dotenv from "dotenv";
dotenv.config();
["MONGODB_URI", "JWT_SECRET"].forEach((k) => {
  if (!process.env[k]) console.warn(`Missing env ${k}`);
});
