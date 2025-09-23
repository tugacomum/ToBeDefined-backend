import jwt from "jsonwebtoken";

export function auth(req, res, next) {
  const token = req.cookies && req.cookies.accessToken;
  if (!token) return res.status(401).json({ success: false, error: "Token não encontrado" });
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.sub; 
    req.userRole = decoded.role;
    next();
  } catch (e) {
    console.error("JWT error:", e);
    return res.status(401).json({ success: false, error: "Invalid token" });
  }
}
