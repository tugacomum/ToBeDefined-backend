const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");

const User = require("../models/user");

router.post("/register", async (req, res) => {
  const user = req.body;
  try {
    const emailExists = await User.findOne({ email: user.email });

    if (emailExists) {
      return res.status(400).json({ message: "Email already exists" });
    }

    const newuser = new User({
      name: user.name,
      email: user.email,
      password: bcrypt.hashSync(user.password, 10),
    });

    await newuser.save();

    res.send(newuser);
  } catch (error) {
    return res.status(400).json({ error });
  }
});

router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email: email });
    if (user) {
      const result = await bcrypt.compare(password, user.password);
      if (result) {
        res.send(user);
      } else {
        return res.status(400).json({ message: "Login failed" });
      }
    } else {
      return res.status(400).json({ message: "Login failed" });
    }
  } catch (error) {
    return res.status(400).json({ error });
  }
});

module.exports = router;