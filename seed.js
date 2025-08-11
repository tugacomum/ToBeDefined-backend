import "./config/env.js"
import mongoose from "mongoose";
import Course from "./models/Course.js";
import TheoryContent from "./models/TheoryContent.js";
import MC from "./models/exercises/MultipleChoice.js";
import TF from "./models/exercises/TrueFalse.js";
import OE from "./models/exercises/OpenEnded.js";
import CODE from "./models/exercises/Code.js";

await mongoose.connect(process.env.MONGODB_URI);

const course = await Course.findOneAndUpdate(
  { slug: "algoritmos-de-procura" },
  {
    title: "Algoritmos de Procura",
    description: "Procura cega e heurística",
    level: "intro",
    slug: "algoritmos-de-procura",
  },
  { upsert: true, new: true }
);

await TheoryContent.deleteMany({ course: course._id });
await MC.deleteMany({ course: course._id });
await TF.deleteMany({ course: course._id });
await OE.deleteMany({ course: course._id });
await CODE.deleteMany({ course: course._id });

const t = await TheoryContent.create({
  course: course._id,
  topic: "busca-a-estrela",
  title: "A* em poucas linhas",
  body: "# A*\nHeurística admissível, f(n)=g(n)+h(n).",
});

await MC.create({
  course: course._id,
  topic: "busca-cega",
  question: "Qual destas é uma procura cega?",
  options: ["A*", "Procura em largura", "IDA*", "SMA*"],
  correctIndexes: [1],
  explanation: "BFS não usa heurística.",
  difficulty: "easy",
});

await TF.create({
  course: course._id,
  topic: "heuristicas",
  statement: "Uma heurística consistente é sempre admissível.",
  isTrue: true,
  explanation: "Consistência implica admissibilidade.",
});

await OE.create({
  course: course._id,
  topic: "conceitos",
  prompt: "Explique a diferença entre procura gulosa e A*.",
  sampleAnswer: "A gulosa usa só h(n); A* usa g(n)+h(n).",
});

await CODE.create({
  course: course._id,
  topic: "utils",
  title: "Soma de dois números",
  prompt: "Implemente `sum(a,b)` que devolve a soma.",
  language: "javascript",
  starterCode: "function sum(a,b){ /* TODO */ }\nmodule.exports = sum;",
  functionName: "sum",
  tests: [
    {
      kind: "unit",
      input: JSON.stringify({ args: [2, 3] }),
      expectedOutput: "5",
      public: true,
    },
    {
      kind: "unit",
      input: JSON.stringify({ args: [-1, 1] }),
      expectedOutput: "0",
      public: false,
    },
  ],
  difficulty: "easy",
});

console.log("Seed concluído.");
await mongoose.disconnect();
process.exit(0);
