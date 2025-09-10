import { Router } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import mongoose from "mongoose";
import { z } from "zod";


import { validate } from "../middleware/validate.js";
import { auth } from "../middleware/auth.js";
import User from "../models/User.js";
import rateLimit from "../middleware/rateLimit.js";
import csrfProtection from "../middleware/csrfProtection.js";


const COOKIE_HTTP_ONLY = true;
const COOKIE_SECURE = false; // true em produção HTTPS
const COOKIE_SAME_SITE = "lax";
const COOKIE_ACCESS_MAX_AGE = 5 * 60 * 1000; // 5 minutos
const COOKIE_REFRESH_MAX_AGE = 15 * 24 * 60 * 60 * 1000; // 15 dias

const ACCESS_TOKEN_EXPIRY_SHORT = "5m"; // Sem remember
const ACCESS_TOKEN_EXPIRY_LONG = "15m"; // Com remember

const r = Router();
const EXPIRATION_MINUTES = 0.5;

// Helpers para refresh tokens
function generateRefreshToken(userId, familyId) {
  return jwt.sign(
    { sub: userId, family: familyId, jti: crypto.randomBytes(16).toString("hex") },
    process.env.JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_EXPIRY_LONG }
  );
}

function verifyRefreshToken(token) {
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return null;
  }
}

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
    keepLoggedIn: z.boolean().optional(),
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
    keepLoggedIn: z.boolean().optional(), // Adiciona este campo
  }),
});

r.post("/login", validate(loginSchema), async (req, res, next) => {
  try {
    const { email, password, keepLoggedIn } = req.data.body;

    const u = await User.findOne({ email });
    if (!u || !(await bcrypt.compare(password, u.passwordHash)))
      return res
        .status(401)
        .json({ success: false, error: "Credenciais inválidas" });

    if (!u.isVerified)
      return res
        .status(403)
        .json({ success: false, error: "Email não verificado" });

    const accessToken = jwt.sign(
      { sub: u.id, role: u.role },
      process.env.JWT_SECRET,
      { expiresIn: ACCESS_TOKEN_EXPIRY_SHORT }
    );

    let refreshToken, refreshExpiryMs, familyId;
    if (keepLoggedIn) {
      familyId = crypto.randomBytes(16).toString("hex");
      refreshToken = jwt.sign(
        { sub: u.id, family: familyId, jti: crypto.randomBytes(16).toString("hex") },
        process.env.JWT_SECRET,
        { expiresIn: ACCESS_TOKEN_EXPIRY_LONG }
      );
      refreshExpiryMs = COOKIE_REFRESH_MAX_AGE; 
      u.refreshTokenFamily = familyId;
      u.refreshTokenJti = jwt.decode(refreshToken).jti;
      await u.save();
    }

    res.cookie("accessToken", accessToken, {
      httpOnly: COOKIE_HTTP_ONLY,
      secure: COOKIE_SECURE,
      sameSite: COOKIE_SAME_SITE,
      maxAge: COOKIE_ACCESS_MAX_AGE
    });
    if (keepLoggedIn) {
      res.cookie("refreshToken", refreshToken, {
        httpOnly: COOKIE_HTTP_ONLY,
        secure: COOKIE_SECURE,
        sameSite: COOKIE_SAME_SITE,
        maxAge: refreshExpiryMs
      });
    } else {
      res.cookie("refreshToken", "", { maxAge: 0 });
    }

    const { passwordHash, ...userWithoutPassword } = u.toObject();

    res.json({
      success: true,
      data: {
        token: accessToken,
        user: userWithoutPassword,
      },
    });
  } catch (e) {
    next(e);
  }
});

r.get("/csrf-token", csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

r.post("/refresh", rateLimit, csrfProtection, async (req, res, next) => {
  try {
    const oldToken = req.cookies.refreshToken;
    if (!oldToken) return res.status(401).json({ success: false, error: "Sem refresh token" });

    const payload = verifyRefreshToken(oldToken);
    if (!payload) return res.status(401).json({ success: false, error: "Refresh token inválido" });

    const user = await User.findById(payload.sub);
    if (!user || user.refreshTokenFamily !== payload.family)
      return res.status(401).json({ reason: "token_reuse" });

    if (user.refreshTokenJti !== payload.jti) {
      // Revoga toda a família
      user.refreshTokenFamily = null;
      user.refreshTokenJti = null;
      await user.save();
      res.clearCookie("accessToken");
      res.clearCookie("refreshToken");
      return res.status(401).json({ reason: "token_reuse" });
    }

    const newToken = generateRefreshToken(user.id, payload.family);
    user.refreshTokenJti = jwt.decode(newToken).jti;
    await user.save();

      const accessToken = jwt.sign(
        { sub: user.id, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: ACCESS_TOKEN_EXPIRY_LONG }
      );

    res.cookie("accessToken", accessToken, {
      httpOnly: COOKIE_HTTP_ONLY,
      secure: COOKIE_SECURE,
      sameSite: COOKIE_SAME_SITE,
      maxAge: COOKIE_ACCESS_MAX_AGE
    });
    res.cookie("refreshToken", newToken, {
      httpOnly: COOKIE_HTTP_ONLY,
      secure: COOKIE_SECURE,
      sameSite: COOKIE_SAME_SITE,
      maxAge: COOKIE_REFRESH_MAX_AGE
    });

    res.json({ success: true });
  } catch (e) {
    next(e);
  }
});

r.post("/logout", async (req, res, next) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (refreshToken) {
      const payload = verifyRefreshToken(refreshToken);
      if (payload) {
        const user = await User.findById(payload.sub);
        if (user && user.refreshTokenFamily === payload.family) {
          user.refreshTokenFamily = null;
          user.refreshTokenJti = null;
          await user.save();
        }
      }
    }
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");
    res.status(200).end();
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

const verifyByEmailSchema = z.object({
  body: z.object({
    email: z.string().email(),
    code: z.string().length(6),
  }),
});

r.post("/verify-email-by-email", validate(verifyByEmailSchema), async (req, res, next) => {
  try {
    const { email, code } = req.data.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, error: "Utilizador não encontrado" });
    }

    if (user.isVerified) {
      return res.status(400).json({ success: false, error: "Utilizador já verificado" });
    }

    if (!user.verificationCode || !user.verificationCodeExpiresAt) {
      return res.status(400).json({ success: false, error: "Nenhum código de verificação encontrado" });
    }

    if (user.verificationCode !== code) {
      return res.status(400).json({ success: false, error: "Código de verificação inválido" });
    }

    user.isVerified = true;
    user.verificationCode = null;
    user.verificationCodeExpiresAt = null;
    await user.save();

    res.json({ success: true, message: "Email verificado com sucesso" });
  } catch (err) {
    next(err);
  }
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

r.post("/resend-verification-email", async (req, res, next) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ success: false, error: "Email é obrigatório" });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ success: false, error: "Utilizador não encontrado" });
    }

    if (user.isVerified) {
      return res.status(400).json({ success: false, error: "Utilizador já verificado" });
    }

    if (!user.verificationCode || new Date() > user.verificationCodeExpiresAt) {
      const code = Math.floor(100000 + Math.random() * 900000).toString();
      user.verificationCode = code;
      user.verificationCodeExpiresAt = new Date(Date.now() + EXPIRATION_MINUTES * 60 * 1000);
      await user.save();
    }

    await sendVerificationEmail(user.email, user.verificationCode);

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
    from: `"ToBeDefined" <${process.env.EMAIL_USER}>`,
    to: toEmail,
    subject: "Código de Verificação",
    text: `O seu código de verificação é: ${code} (válido por 30 segundos)`,
  };

  await transporter.sendMail(mailOptions);
}

async function sendResetPasswordEmail(user) {
  const code = generateVerificationCode();
  user.resetPasswordToken = code;
  user.resetPasswordExpiresAt = new Date(Date.now() + 30 * 1000); 
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
    text: `O seu código para redefinir a password é: ${code} (válido por 30 segundos).`,
  });
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
        .json({ success: false, error: "Código de verificação expirado" });
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

    await sendResetPasswordEmail(user);

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

r.post("/resend-reset-password-code", async (req, res, next) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user)
      return res.status(404).json({ success: false, error: "Utilizador não encontrado" });

    await sendResetPasswordEmail(user);

    res.json({ success: true, message: "Código de redefinição reenviado com sucesso" });
  } catch (err) {
    next(err);
  }
});

r.get("/profile", auth, async (req, res, next) => {
  const token = req.cookies.accessToken;
  if (!token) return res.status(401).json({ success: false, error: "Sem token de acesso" });
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(payload.sub).lean();
    if (!user) return res.status(404).json({ success: false, error: "Utilizador não encontrado" });

    const { passwordHash, ...userWithoutPassword } = user;
    res.json({ success: true, data: userWithoutPassword });
  } catch (e) {
    console.error("Erro:", e);
    next(e);
  }
});

export default r;
