const express = require('express');
require('./db');

const usersRoute = require('./routes/usersRouter');

const app = express();

app.use(express.json());
app.use('/api/users', usersRoute);

const port = process.env.PORT || 5000;

app.listen(port, () => console.log(`Server running on port ${port}`));
