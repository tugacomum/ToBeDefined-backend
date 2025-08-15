import { Router } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import { z } from "zod";

import { validate } from "../middleware/validate.js";
import User from "../models/User.js";

const r = Router();
const EXPIRATION_MINUTES = 10;

function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString(); 
}

async function sendVerificationCode(user) {
  const code = generateVerificationCode();
  user.verificationCode = code;
  user.verificationCodeExpiresAt = new Date(
    Date.now() + EXPIRATION_MINUTES * 60 * 1000
  );
  await user.save();

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  await transporter.sendMail({
    from: `"App" <${process.env.EMAIL_USER}>`,
    to: user.email,
    subject: "Código de Verificação",
    text: `O seu código de verificação é: ${code} (válido por ${EXPIRATION_MINUTES} minutos)`,
  });
}

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

    await sendVerificationCode(u);

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

    if (!u.isVerified)
      return res
        .status(403)
        .json({ success: false, error: "Email not verified" });

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

const verifySchema = z.object({
  body: z.object({
    userId: z.string(),
    code: z.string().length(6),
  }),
});

r.post("/verify-email", validate(verifySchema), async (req, res, next) => {
  try {
    const { userId, code } = req.data.body;
    const user = await User.findById(userId);

    if (!user)
      return res.status(404).json({ success: false, error: "User not found" });

    if (user.isVerified)
      return res.status(400).json({ success: false, error: "User already verified" });

    if (!user.verificationCode || !user.verificationCodeExpiresAt)
      return res.status(400).json({ success: false, error: "No verification code found" });

    if (new Date() > user.verificationCodeExpiresAt)
      return res.status(400).json({ success: false, error: "Verification code expired" });

    if (user.verificationCode !== code)
      return res.status(400).json({ success: false, error: "Invalid verification code" });

    user.isVerified = true;
    user.verificationCode = null;
    user.verificationCodeExpiresAt = null;
    await user.save();

    res.json({ success: true, message: "Email verified successfully" });
  } catch (e) {
    next(e);
  }
});

const resendSchema = z.object({
  body: z.object({
    userId: z.string(),
  }),
});

r.post("/resend-verification", validate(resendSchema), async (req, res, next) => {
  try {
    const { userId } = req.data.body;
    const user = await User.findById(userId);

    if (!user)
      return res.status(404).json({ success: false, error: "User not found" });

    if (user.isVerified)
      return res.status(400).json({ success: false, error: "User already verified" });

    await sendVerificationCode(user);

    res.json({ success: true, message: "Verification code resent" });
  } catch (e) {
    next(e);
  }
});

const forgotPasswordSchema = z.object({
  body: z.object({
    email: z.string().email(),
  }),
});

r.post("/forgot-password", validate(forgotPasswordSchema), async (req, res, next) => {
  try {
    const { email } = req.data.body;
    const user = await User.findOne({ email });
    if (!user)
      return res.status(404).json({ success: false, error: "User not found" });

    const code = generateVerificationCode();
    user.resetPasswordToken = code;
    user.resetPasswordExpiresAt = new Date(Date.now() + 15 * 60 * 1000);
    await user.save();

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    await transporter.sendMail({
      from: `"App" <${process.env.EMAIL_USER}>`,
      to: user.email,
      subject: "Reset de Password",
      text: `O seu código para redefinir a password é: ${code} (válido por 15 minutos)`,
    });

    res.json({ success: true, message: "Password reset code sent" });
  } catch (err) {
    next(err);
  }
});

const resetPasswordSchema = z.object({
  body: z.object({
    email: z.string().email(),
    code: z.string().length(6),
    newPassword: z.string().min(6).max(128),
  }),
});

r.post("/reset-password", validate(resetPasswordSchema), async (req, res, next) => {
  try {
    const { email, code, newPassword } = req.data.body;
    const user = await User.findOne({ email });
    if (!user)
      return res.status(404).json({ success: false, error: "User not found" });

    if (
      !user.resetPasswordToken ||
      !user.resetPasswordExpiresAt ||
      new Date() > user.resetPasswordExpiresAt
    ) {
      return res.status(400).json({ success: false, error: "Reset code expired or not found" });
    }

    if (user.resetPasswordToken !== code)
      return res.status(400).json({ success: false, error: "Invalid reset code" });

    user.passwordHash = await bcrypt.hash(newPassword, 11);
    user.resetPasswordToken = null;
    user.resetPasswordExpiresAt = null;
    await user.save();

    res.json({ success: true, message: "Password updated successfully" });
  } catch (err) {
    next(err);
  }
});

export default r;
