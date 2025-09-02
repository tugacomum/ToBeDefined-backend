import { Router } from "express";
import { z } from "zod";

import { validate } from "../middleware/validate.js";
import Course from "../models/Course.js";

const r = Router();

const courseSchema = z.object({
  body: z.object({
    title: z.string().min(2).max(100),
    type: z.string().min(2).max(100),
  }),
});

r.post("/createCourse", validate(courseSchema), async (req, res, next) => {
  try {
    const { title, type } = req.data.body;

    const exists = await Course.findOne({ title });
    if (exists) {
      return res
        .status(400)
        .json({ error: "Já existe um curso com esse título" });
    }

    await Course.create({ title, type });

    res.status(201).json({ success: true });
  } catch (e) {
    next(e);
  }
});

r.get("/courses", async (_req, res, next) => {
  try {
    const list = await Course.find();
    res.json({ success: true, data: list });
  } catch (e) {
    next(e);
  }
});

r.get("/coursesByType", async (req, res, next) => {
  try {
    const courses = await Course.find().sort({ type: 1, title: 1 });

    const grouped = courses.reduce((acc, course) => {
      if (!acc[course.type]) acc[course.type] = [];
      acc[course.type].push({ id: course._id, title: course.title });
      return acc;
    }, {});

    res.json({ success: true, data: grouped });
  } catch (e) {
    next(e);
  }
});

export default r;
