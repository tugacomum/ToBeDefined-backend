const enums = {
  role: ["student", "admin"],
  exerciseType: ["code", "open", "true_false", "multiple"],
  enrollmentStatus: ["active", "completed", "dropped"],
  attemptStatus: ["in_progress", "submitted", "graded", "returned"],
  courseType: ["ctesp", "licenciatura", "mestrado", "doutoramento"],
};

function requiredMsg(field) {
  return `${field} é obrigatório.`;
}

export default enums;
export { requiredMsg };
