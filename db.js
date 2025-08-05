const mongoose = require('mongoose');
require('dotenv').config();

var mongoURL = process.env.MONGO_URI;

mongoose.connect(mongoURL, { useUnifiedTopology: true, useNewUrlParser: true });

var connection = mongoose.connection;

connection.on('error', () => {
    console.log('Mongo DB Connection failed')
})

connection.on('connected', () => {
    console.log('Mongo DB Connection Sucessfull')
})

module.exports = mongoose;