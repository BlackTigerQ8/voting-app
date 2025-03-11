const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const { User } = require("./models/userModel");
const connectDB = require("./config/db.js");

connectDB();

// Function to create Admin
const createAdmin = async () => {
  try {
    // Check if admin already exists
    const admin = await User.findOne({ role: "Admin" });
    if (admin) {
      console.log("Admin account already exists");
      return;
    }

    // Create new admin user
    const newAdmin = new User({
      firstName: "Abdullah",
      lastName: "Alenezi",
      phone: "66850080",
      dateOfBirth: "1995-07-21",
      email: "admin@gmail.com",
      password: "123123",
      confirmPassword: "123123",
      role: "Admin",
    });

    await newAdmin.save();
    console.log("Admin account created successfully");
  } catch (error) {
    console.error("Error creating admin account", error);
  }
};

function generateRandomDOB(startYear = 1980, endYear = 2000) {
  const year =
    Math.floor(Math.random() * (endYear - startYear + 1)) + startYear;
  const month = Math.floor(Math.random() * 12);
  const day = Math.floor(Math.random() * 28) + 1; // Days between 1 and 28 (to avoid invalid dates)
  return new Date(year, month, day).toISOString().split("T")[0]; // returns in YYYY-MM-DD format
}

// Function to delete all users
const deleteAllUsers = async () => {
  try {
    await User.deleteMany({});
    console.log("All users deleted");
  } catch (error) {
    console.error("Error deleting users:", error);
  } finally {
    mongoose.connection.close();
  }
};

// Uncomment the relevant function call as needed
createAdmin();
// deleteAllUsers();
