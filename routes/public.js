import { Router } from "express";
import Course from "../models/Course.js";
import TheoryContent from "../models/TheoryContent.js";
import ExerciseMC from "../models/exercises/MultipleChoice.js";
import ExerciseTF from "../models/exercises/TrueFalse.js";
import ExerciseOE from "../models/exercises/OpenEnded.js";
import ExerciseCode from "../models/exercises/Code.js";

const r = Router();

r.get("/courses", async (_req, res, next) => {
  try {
    const list = await Course.find()
      .select("title description level slug")
      .lean();
    res.json({ success: true, data: list });
  } catch (e) {
    next(e);
  }
});

r.get("/theory/:id", async (req, res, next) => {
  try {
    const doc = await TheoryContent.findById(req.params.id).lean();
    if (!doc)
      return res
        .status(404)
        .json({ success: false, error: "Theory content not found" });
    res.json({ success: true, data: doc });
  } catch (e) {
    next(e);
  }
});

async function oneCodeSample() {
  const doc = await ExerciseCode.findOne().lean();
  if (!doc) return null;
  const { tests, ...rest } = doc;
  return { ...rest, tests: (tests || []).filter((t) => t.public) }; // só testes públicos
}

r.get("/exercises/sample", async (req, res, next) => {
  try {
    const type = String(req.query.type || "").toLowerCase();
    if (!type) {
      const [mc, tf, oe, code] = await Promise.all([
        ExerciseMC.findOne().lean(),
        ExerciseTF.findOne().lean(),
        ExerciseOE.findOne().lean(),
        oneCodeSample(),
      ]);
      return res.json({
        success: true,
        data: { multipleChoice: mc, trueFalse: tf, openEnded: oe, code },
      });
    }
    if (type === "multiple_choice")
      return res.json({
        success: true,
        data: await ExerciseMC.findOne().lean(),
      });
    if (type === "true_false")
      return res.json({
        success: true,
        data: await ExerciseTF.findOne().lean(),
      });
    if (type === "open_ended")
      return res.json({
        success: true,
        data: await ExerciseOE.findOne().lean(),
      });
    if (type === "code")
      return res.json({ success: true, data: await oneCodeSample() });
    res.status(400).json({ success: false, error: "Unknown type" });
  } catch (e) {
    next(e);
  }
});

export default r;
