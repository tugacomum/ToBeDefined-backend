import csurf from "csurf";

const csrfProtection = csurf({
  cookie: true, // usa cookie para guardar o token CSRF
});

export default csrfProtection;