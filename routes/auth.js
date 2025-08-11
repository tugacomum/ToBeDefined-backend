import { Router } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { z } from "zod";
import { validate } from "../middleware/validate.js";
import User from "../models/User.js";

const r = Router();

const registerSchema = z.object({
  body: z.object({
    name: z.string().min(2),
    email: z.string().email(),
    password: z.string().min(6).max(128),
  }),
});

r.post("/register", validate(registerSchema), async (req, res, next) => {
  try {
    const { name, email, password } = req.data.body;
    if (await User.findOne({ email }))
      return res
        .status(409)
        .json({ success: false, error: "Email already registered" });
    const passwordHash = await bcrypt.hash(password, 11);
    const u = await User.create({ name, email, passwordHash });
    res.status(201).json({
      success: true,
      data: { id: u.id, name: u.name, email: u.email },
    });
  } catch (e) {
    next(e);
  }
});

const loginSchema = z.object({
  body: z.object({
    email: z.string().email(),
    password: z.string().min(6),
  }),
});

r.post("/login", validate(loginSchema), async (req, res, next) => {
  try {
    console.log("Login attempt with data:", req.data.body);
    const { email, password } = req.data.body;
    const u = await User.findOne({ email });
    if (!u || !(await bcrypt.compare(password, u.passwordHash)))
      return res
        .status(401)
        .json({ success: false, error: "Invalid credentials" });
    const token = jwt.sign(
      { sub: u.id, role: u.role },
      process.env.JWT_SECRET,
      { expiresIn: "30m" }
    );
    res.json({ success: true, data: { token } });
  } catch (e) {
    next(e);
  }
});

export default r;
