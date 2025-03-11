const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const USER_ROLES = ["SuperAdmin", "Admin", "Voter"];

const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: [true, "You need to enter your first name"],
  },
  lastName: {
    type: String,
    required: [true, "You need to enter your last name"],
  },
  email: {
    type: String,
    unique: true,
    trim: true,
    required: [true, "Email is required for future login"],
  },
  phone: {
    type: Number,
    required: [true, "Phone number is required"],
    unique: true,
    validate: {
      validator: function (v) {
        return /^\d{8}$/.test(v.toString());
      },
      message: (props) =>
        `${props.value} is not a valid phone number! Must be exactly 8 digits`,
    },
  },
  idNumber: {
    type: Number,
    required: [true, "ID number is required"],
    unique: true,
    validate: {
      validator: function (v) {
        return /^\d{12}$/.test(v.toString());
      },
      message: (props) =>
        `${props.value} is not a valid ID number! Must be exactly 12 digits`,
    },
  },
  role: {
    type: String,
    enum: USER_ROLES,
    required: true,
    default: "Voter",
  },
  idImage: {
    type: String,
  },
  password: {
    type: String,
    required: [true, "Password is required"],
    minlength: [6, "Password must be at least 6 characters long"],
  },
  confirmPassword: {
    type: String,
    required: [true, "Please confirm your passowrd"],
    // This validator only works on CREATE and SAVE!!!
    validate: {
      validator: function (input) {
        return input === this.password;
      },
      message: "Passwords did not match!",
    },
  },
  createdAt: {
    type: Date,
    default: Date.now(),
  },
});

// Mongoose middleware to hash the password before saving
userSchema.pre("save", async function (next) {
  // Only run this function if password was actually modified
  if (!this.isModified("password")) return next();
  // Generate a salt and hash the password
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  //   Delete passwordConfirm field
  this.confirmPassword = undefined;

  // To remove commas from identification number
  if (this.identification && typeof this.identification === "string") {
    this.identification = this.identification.replace(/,/g, "");
  }
  next();
});

module.exports = { User: mongoose.model("User", userSchema), USER_ROLES };
