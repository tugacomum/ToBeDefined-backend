import { Router } from "express";

import Module from "../models/Module.js";
import Subject from "../models/Subject.js";
import Exercise from "../models/Exercise.js";
import ExerciseRevision from "../models/ExerciseRevision.js";
import Attempt from "../models/Attempt.js";
import EnrollmentSubject from "../models/EnrollmentSubject.js";

const router = Router();

// GET /public/subjects
router.get("/subjects", async (req, res) => {
  try {
    const subjects = await Subject.find({ active: true }).select(
      "title description"
    );
    res.json(subjects);
  } catch (error) {
    console.error("Error fetching subjects:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /public/subjects/:subjectId/modules
router.get("/subjects/:subjectId/modules", async (req, res) => {
  const { subjectId } = req.params;
  try {
    const modules = await Module.find({ subjectId })
      .select("title order")
      .sort({ order: 1 });
    res.json(modules);
  } catch (error) {
    console.error("Error fetching modules:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /public/modules/:moduleId/exercises
router.get("/modules/:moduleId/exercises", async (req, res) => {
  const { moduleId } = req.params;
  try {
    const module = await Module.findById(moduleId).populate({
      path: "exerciseIds",
      select: "title type difficulty points",
    });
    if (!module) {
      return res.status(404).json({ error: "Module not found" });
    }
    res.json(module.exerciseIds);
  } catch (error) {
    console.error("Error fetching exercises:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
