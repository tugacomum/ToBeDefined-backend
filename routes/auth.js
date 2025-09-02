import { Router } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import mongoose from "mongoose";
import { z } from "zod";

import { validate } from "../middleware/validate.js";
import { auth } from "../middleware/auth.js";
import User from "../models/User.js";

const r = Router();
const EXPIRATION_MINUTES = 0.5;

function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString(); 
}

async function sendVerificationCode(user) {
  const code = generateVerificationCode()
  user.verificationCode = code;
  user.verificationCodeExpiresAt = new Date(Date.now() + EXPIRATION_MINUTES * 60 * 1000);
  await user.save();

  await sendVerificationEmail(user.email, code);
}

const registerSchema = z.object({
  body: z.object({
    email: z.string().email(),
    courseId: z.string().min(24).max(24),
    password: z.string().min(8).max(128),
  }),
});

r.post("/register", validate(registerSchema), async (req, res, next) => {
  try {
    const { email, courseId, password } = req.data.body;

    if (await User.findOne({ email }))
      return res
        .status(409)
        .json({ success: false, error: "Email já registado" });

    const passwordHash = await bcrypt.hash(password, 11);
    const u = await User.create({ email, courseId, passwordHash });

    await sendVerificationCode(u);

    res.status(201).json({ success: true, userId: u._id });
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
    const { email, password } = req.data.body;

    const u = await User.findOne({ email });
    if (!u || !(await bcrypt.compare(password, u.passwordHash)))
      return res
        .status(401)
        .json({ success: false, error: "Credenciais inválidas" });

    if (!u.isVerified)
      return res
        .status(403)
        .json({ success: false, error: "Email não verificado" });

    const token = jwt.sign(
      { sub: u.id, role: u.role },
      process.env.JWT_SECRET,
      { expiresIn: "30m" }
    );

    const { passwordHash, ...userWithoutPassword } = u.toObject();

    res.json({
      success: true,
      data: {
        token,
        user: userWithoutPassword,
      },
    });
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
      return res.status(404).json({ success: false, error: "Utilizador não encontrado" });

    if (user.isVerified)
      return res.status(400).json({ success: false, error: "Utilizador já verificado" });

    if (!user.verificationCode || !user.verificationCodeExpiresAt)
      return res.status(400).json({ success: false, error: "Nenhum código de verificação encontrado" });

    if (new Date() > user.verificationCodeExpiresAt)
      return res.status(400).json({ success: false, error: "Código de verificação expirado" });

    if (user.verificationCode !== code)
      return res.status(400).json({ success: false, error: "Código de verificação inválido" });

    user.isVerified = true;
    user.verificationCode = null;
    user.verificationCodeExpiresAt = null;
    await user.save();

    res.json({ success: true, message: "Email verificado com sucesso" });
  } catch (e) {
    next(e);
  }
});

r.post("/resend-verification-code", async (req, res, next) => {
  try {
    const { userId } = req.body;
    const user = await User.findById(userId);

    if (!user) return res.status(404).json({ success: false, error: "Utilizador não encontrado" });
    if (user.isVerified) return res.status(400).json({ success: false, error: "Utilizador já verificado" });

    if (user.verificationCodeExpiresAt && new Date() < user.verificationCodeExpiresAt) {
      return res.status(400).json({ success: false, error: "Código de verificação ainda não expirou" });
    }

    const newCode = generateVerificationCode()
    user.verificationCode = newCode;
    user.verificationCodeExpiresAt = new Date(Date.now() + EXPIRATION_MINUTES * 60 * 1000);
    await user.save();

    await sendVerificationEmail(user.email, newCode);

    res.json({ success: true, message: "Código de verificação reenviado com sucesso" });
  } catch (err) {
    next(err);
  }
});

export async function sendVerificationEmail(toEmail, code) {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const mailOptions = {
    from: `"App" <${process.env.EMAIL_USER}>`,
    to: toEmail,
    subject: "Código de Verificação",
    text: `O seu código de verificação é: ${code} (válido por 30 segundos)`,
  };

  await transporter.sendMail(mailOptions);
}

const verifyResetCodeSchema = z.object({
  body: z.object({
    email: z.string().email(),
    code: z.string().length(6),
  }),
});

r.post("/verify-reset-code", validate(verifyResetCodeSchema), async (req, res, next) => {
  try {
    const { email, code } = req.data.body;
    const user = await User.findOne({ email });
    if (!user)
      return res.status(404).json({ success: false, error: "Utilizador não encontrado" });

    if (
      !user.resetPasswordToken ||
      !user.resetPasswordExpiresAt ||
      new Date() > user.resetPasswordExpiresAt
    ) {
      return res
        .status(400)
        .json({ success: false, error: "Código de redefinição expirado ou não encontrado" });
    }

    if (user.resetPasswordToken !== code)
      return res
        .status(400)
        .json({ success: false, error: "Código de redefinição inválido" });

    const resetToken = jwt.sign(
      { sub: user.id, action: "reset-password" },
      process.env.JWT_SECRET,
      { expiresIn: "15m" }
    );

    res.json({ success: true, data: { resetToken } });
  } catch (err) {
    next(err);
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
      return res.status(404).json({ success: false, error: "Utilizador não encontrado" });

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

    res.json({ success: true, message: "Código de redefinição de password enviado com sucesso" });
  } catch (err) {
    next(err);
  }
});

const resetPasswordSchema = z.object({
  body: z.object({
    token: z.string(),
    newPassword: z.string().min(6).max(128),
  }),
});

r.post("/reset-password", validate(resetPasswordSchema), async (req, res, next) => {
  try {
    const { token, newPassword } = req.data.body;

    let payload;
    try {
      payload = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ success: false, error: "Token inválido ou expirado" });
    }

    if (payload.action !== "reset-password")
      return res.status(401).json({ success: false, error: "Ação de token inválida" });

    const user = await User.findById(payload.sub);
    if (!user)
      return res.status(404).json({ success: false, error: "Utilizador não encontrado" });

    user.passwordHash = await bcrypt.hash(newPassword, 11);
    user.resetPasswordToken = null;
    user.resetPasswordExpiresAt = null;
    await user.save();

    res.json({ success: true, message: "Password atualizada com sucesso" });
  } catch (err) {
    next(err);
  }
});

r.get("/profile", auth, async (req, res, next) => {
  try {
    const u = await User.findById(new mongoose.Types.ObjectId(req.userId)).select("-passwordHash");
    if (!u) return res.status(404).json({ success: false, error: "Utilizador não encontrado" });

    res.json({ success: true, data: u });
  } catch (e) {
    console.error("Erro:", e);
    next(e);
  }
});

export default r;
