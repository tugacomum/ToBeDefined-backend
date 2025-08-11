export const validate = (schema) => (req, _res, next) => {
  try {
    req.data = schema.parse({
      body: req.body,
      query: req.query,
      params: req.params,
    });
    next();
  } catch (e) {
    e.status = 400;
    next(e);
  }
};
