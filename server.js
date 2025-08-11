import dotenv from "dotenv";
dotenv.config();

import express from "express";
import helmet from "helmet";
import cors from "cors";

import { connectDB } from "./config/db.js";
import authRoutes from "./routes/auth.js";
import publicRoutes from "./routes/public.js";

import swaggerUi from "swagger-ui-express";
import { readFileSync } from "fs";
import { parse } from "yaml";

const openapiSpec = parse(
  readFileSync(new URL("./openapi.yaml", import.meta.url), "utf8")
);

const app = express();
const port = process.env.PORT || 3000;

// Hardening básico e parsing
app.disable("x-powered-by");
app.use(helmet());
const allowed = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(",")
  : ["*"];

app.use(
  cors({
    origin(origin, cb) {
      if (!origin || allowed.includes("*") || allowed.includes(origin))
        return cb(null, true);
      return cb(new Error("Not allowed by CORS"));
    },
    credentials: true,
  })
);

app.use(express.json());

// Health-check
app.get("/health", (_req, res) => res.json({ status: "ok" }));

// Rotas da API
app.use("/api/auth", authRoutes);
app.use("/api", publicRoutes);

// 404 para caminhos /api desconhecidos
app.use("/api", (_req, res) =>
  res.status(404).json({ success: false, error: "Not Found" })
);

// Handler de erros
app.use((err, _req, res, _next) => {
  console.error(err);
  res
    .status(err.status || 500)
    .json({ success: false, error: err.message || "Internal Server Error" });
});

// Arranque após ligação à BD
connectDB()
  .then(() => {
    app.listen(port, () =>
      console.log(`API a escutar em http://localhost:${port}`)
    );
  })
  .catch((err) => {
    console.error("Falha ao ligar à base de dados:", err);
    process.exit(1);
  });

app.use(
  "/docs",
  swaggerUi.serve,
  swaggerUi.setup(openapiSpec, {
    customSiteTitle: "ToBeDefined – API Docs",
    customCss: ".topbar { display: none }",
  })
);
export default app;
