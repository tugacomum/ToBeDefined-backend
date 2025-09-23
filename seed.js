import mongoose from "mongoose";
import dotenv from "dotenv";
dotenv.config();

import Course from "./models/Course.js";
import Subject from "./models/Subject.js";
import Module from "./models/Module.js";
import User from "./models/User.js";
import Exercise from "./models/Exercise.js";
import ExerciseRevision from "./models/ExerciseRevision.js";
import bcrypt from "bcryptjs";

async function seed() {
  await mongoose.connect(process.env.MONGODB_URI);

  // Limpar coleções
  await Promise.all([
    Course.deleteMany({}),
    Subject.deleteMany({}),
    Module.deleteMany({}),
    User.deleteMany({}),
    Exercise.deleteMany({}),
    ExerciseRevision.deleteMany({}),
  ]);

  // Cursos
  const cursos = await Course.insertMany([
    {
      title: "Algoritmos de Procura",
      slug: "algoritmos-procura",
      description: "Procura cega e heurística",
      type: "ctesp",
      isActive: true,
    },
    {
      title: "Estruturas de Dados",
      slug: "estruturas-dados",
      description: "Listas, árvores e grafos",
      type: "licenciatura",
      isActive: true,
    },
  ]);

  // Disciplinas
  const disciplinas = await Subject.insertMany([
    {
      title: "Introdução à Programação",
      slug: "introducao-programacao",
      description: "Primeiros passos em programação",
      isActive: true,
    },
    {
      title: "Teoria dos Grafos",
      slug: "teoria-grafos",
      description: "Conceitos fundamentais de grafos",
      isActive: true,
    },
  ]);

  // Módulos
  const modulos = await Module.insertMany([
    {
      subjectId: disciplinas[0]._id,
      title: "Variáveis e Tipos",
      order: 1,
      theory: {
        blocks: [
          {
            type: "text",
            data: "Neste módulo vais aprender sobre variáveis e tipos de dados.",
          },
        ],
      },
      exerciseIds: [],
    },
    {
      subjectId: disciplinas[1]._id,
      title: "Representação de Grafos",
      order: 1,
      theory: {
        blocks: [
          {
            type: "text",
            data: "Aprende a representar grafos em memória.",
          },
        ],
      },
      exerciseIds: [],
    },
  ]);

  // Exercícios
  const exercicios = await Exercise.insertMany([
    {
      subjectId: disciplinas[0]._id,
      moduleId: modulos[0]._id,
      title: "Qual destas é uma variável válida em JavaScript?",
      type: "multiple",
      difficulty: "easy",
      points: 1,
      tags: ["variáveis", "javascript"],
      currentVersion: 1,
      active: true,
    },
    {
      subjectId: disciplinas[1]._id,
      moduleId: modulos[1]._id,
      title: "Um grafo pode ser dirigido?",
      type: "true_false",
      difficulty: "easy",
      points: 1,
      tags: ["grafos"],
      currentVersion: 1,
      active: true,
    },
    {
      subjectId: disciplinas[0]._id,
      moduleId: modulos[0]._id,
      title: "Explique a diferença entre let e var.",
      type: "open",
      difficulty: "medium",
      points: 2,
      tags: ["variáveis", "javascript"],
      currentVersion: 1,
      active: true,
    },
    {
      subjectId: disciplinas[0]._id,
      moduleId: modulos[0]._id,
      title: "Soma de dois números",
      type: "code",
      difficulty: "easy",
      points: 2,
      tags: ["funções", "javascript"],
      currentVersion: 1,
      active: true,
    },
  ]);

  // Revisões dos Exercícios
  await ExerciseRevision.insertMany([
    {
      exerciseId: exercicios[0]._id,
      version: 1,
      statement: "Qual destas é uma variável válida em JavaScript?",
      type: "multiple",
      spec_multiple: {
        options: ["2nome", "_nome", "var-nome", "nome!"],
        answers: ["_nome"],
        shuffle: true,
      },
    },
    {
      exerciseId: exercicios[1]._id,
      version: 1,
      statement: "Um grafo pode ser dirigido?",
      type: "true_false",
      spec_true_false: {
        answer: true,
      },
    },
    {
      exerciseId: exercicios[2]._id,
      version: 1,
      statement: "Explique a diferença entre let e var.",
      type: "open",
      spec_open: {
        rubric: [
          "let tem escopo de bloco",
          "var tem escopo de função",
          "let não permite redeclaração no mesmo bloco",
        ],
        maxChars: 500,
        keywords: ["escopo", "bloco", "função", "redeclaração"],
      },
    },
    {
      exerciseId: exercicios[3]._id,
      version: 1,
      statement:
        "Implemente uma função sum(a, b) que devolve a soma dos dois números.",
      type: "code",
      spec_code: {
        language: "javascript",
        timeoutSec: 5,
        memoryMb: 128,
        runtime: "default",
        setup: "",
        teardown: "",
        tests: [
          {
            kind: "unit",
            functionName: "sum",
            args: [2, 3],
            expected: 5,
            compare: "deepEqual",
            public: true,
            weight: 1,
          },
        ],
      },
    },
  ]);

  // Atualizar exerciseIds nos módulos
  await Module.findByIdAndUpdate(modulos[0]._id, {
    $set: {
      exerciseIds: [exercicios[0]._id, exercicios[2]._id, exercicios[3]._id],
    },
  });
  await Module.findByIdAndUpdate(modulos[1]._id, {
    $set: { exerciseIds: [exercicios[1]._id] },
  });

  // Utilizadores
  const passwordHash = await bcrypt.hash("admin0", 11);
  await User.create([
    {
      firstName: "João",
      lastName: "Cervaluto",
      email: "cervaluto@tobedefined.pt",
      passwordHash,
      roles: ["student"],
      isVerified: true,
      status: "active",
    },
    {
      firstName: "Xavier",
      lastName: "Otávio",
      email: "admin@tobedefined.pt",
      passwordHash,
      roles: ["admin"],
      isVerified: true,
      status: "active",
    },
  ]);

  console.log("Base de dados populada com sucesso!");
  await mongoose.disconnect();
}

seed().catch((e) => {
  console.error(e);
  process.exit(1);
});
