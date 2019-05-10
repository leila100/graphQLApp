const bcrypt = require("bcryptjs");
const validator = require("validator");
const jwt = require("jsonwebtoken");

const User = require("../models/user");

module.exports = {
  createUser: async function(args, req) {
    const { email, name, password } = args.userInput;
    const errors = [];
    if (!validator.isEmail(email)) {
      errors.push({ message: "Email is invalid!" });
    }
    if (validator.isEmpty(password) || !validator.isLength(password, { min: 5 })) {
      errors.push({ message: "Password should be at least 5 characters long!" });
    }
    if (errors.length > 0) {
      const error = new Error("Invalid Input.");
      error.data = errors;
      error.code = 422;
      throw error;
    }
    const existingUser = await User.findOne({ email: email });
    if (existingUser) {
      const error = new Error("User exists already!");
      throw error;
    }
    const hashedPass = await bcrypt.hash(password, 12);
    const user = new User({
      email: email,
      name: name,
      password: hashedPass
    });
    const createdUser = await user.save();
    return { ...createdUser._doc, _id: createdUser._id.toString() };
  },

  login: async function({ email, password }, req) {
    const user = await User.findOne({ email: email });
    if (!user) {
      const error = new Error("User not found!");
      error.code = 401;
      throw error;
    }
    const isEqual = await bcrypt.compare(password, user.password);
    if (!isEqual) {
      const error = new Error("Invalid password!");
      error.code = 401;
      throw error;
    }
    const token = jwt.sign(
      {
        userId: user._id.toString(),
        email: user.email
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    return { token: token, userId: user._id.toString() };
  }
};
