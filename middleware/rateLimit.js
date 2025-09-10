import rateLimit from "express-rate-limit";

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // máximo de 100 requisições por IP
  message: "Demasiados pedidos, tente novamente mais tarde.",
  standardHeaders: true,
  legacyHeaders: false,
});

export default limiter;