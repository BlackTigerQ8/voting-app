const { User } = require("../models/userModel");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

// @desc    Get all users
// @route   GET /api/users
// @access  Private/Admin
const getAllusers = async (req, res) => {
  try {
    let query = {};
    const { role } = req.query;

    if (req.user.role === "Admin" || req.user.role === "SuperAdmin") {
      // If a specific role is requested (e.g., for coach selection)
      if (req.query.role) {
        query.role = req.query.role;
      }
    } else if (req.user.role === "Voter") {
      // Allow customers to see only their own profile
      query = { _id: req.user._id };
    } else {
      // If user is neither Admin nor Barista, return unauthorized
      return res.status(403).json({
        status: "Error",
        message: "Not authorized to access user list",
      });
    }

    const users = await User.find(query);

    res.status(200).json({
      status: "Success",
      data: {
        users,
      },
    });
  } catch (error) {
    res.status(500).json({
      status: "Error",
      message: error.message,
    });
  }
};

// @desc    Get user profile
// @route   GET /api/users/:id
// @access  Private
const getUser = async (req, res) => {
  try {
    const user = await User.findById(req.params.id);

    // Check if the user exists
    if (!user) {
      return res.status(404).json({
        status: "Error",
        message: "User not found",
      });
    }

    // Check if the user is accessing their own data or is an admin
    if (
      req.user.id !== req.params.id &&
      req.user.role !== "Admin" &&
      req.user.role !== "SuperAdmin"
    ) {
      return res.status(403).json({
        status: "Error",
        message: "You do not have permission to access this user's data",
      });
    }

    res.status(200).json({
      stauts: "Success",
      data: { ...user._doc, idImagePath: user.idImage },
    });
  } catch (error) {
    res.status(500).json({
      status: "Error",
      message: error.message,
    });
  }
};

// @desc    Register a new user
// @route   POST /api/users
// @access  Private/Admin
const createUser = async (req, res) => {
  try {
    // If someone is logged in (admin), they can set any role
    if (
      req.user &&
      (req.user.role === "Admin" || req.user.role === "SuperAdmin")
    ) {
      // Admin can create any type of user
      const uploadedFile = req.file;
      const filePath = uploadedFile ? uploadedFile.path : null;
      const newUser = await User.create({
        firstName: req.body.firstName,
        lastName: req.body.lastName,
        email: req.body.email,
        phone: req.body.phone,
        idNumber: req.body.idNumber,
        role: req.body.role, // Admin can set any role
        password: req.body.password,
        confirmPassword: req.body.confirmPassword,
        idImage: filePath,
      });

      await newUser.save({ validateBeforeSave: false });

      return res.status(201).json({
        status: "Success",
        data: { user: newUser },
      });
    }

    // For public registration, force role to be "Voter"
    const uploadedFile = req.file;
    const filePath = uploadedFile ? uploadedFile.path : null;
    const newUser = await User.create({
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      email: req.body.email,
      phone: req.body.phone,
      idNumber: req.body.idNumber,
      role: "Voter", // Force role to be Voter for public registration
      password: req.body.password,
      confirmPassword: req.body.confirmPassword,
      idImage: filePath,
    });

    await newUser.save({ validateBeforeSave: false });

    res.status(201).json({
      status: "Success",
      data: { user: newUser },
    });
  } catch (error) {
    res.status(500).json({
      status: "Error",
      message: error.message,
    });
  }
};

// @desc    Update user profile
// @route   PUT /api/users/:id
// @access  Private
const updateUser = async (req, res) => {
  try {
    // Check if the user is accessing their own data or is an admin
    if (
      req.user.id !== req.params.id &&
      req.user.role !== "Admin" &&
      req.user.role !== "SuperAdmin"
    ) {
      return res.status(403).json({
        status: "Error",
        message: "You do not have permission to access this user's data",
      });
    }

    const uploadedFile = req.file;
    const filePath = uploadedFile ? uploadedFile.path : null;

    // Prepare the updated data
    const updateData = req.file
      ? { ...req.body, idImage: filePath }
      : { ...req.body };

    // Check if password is included in the request body and hash it
    if (req.body.password) {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(req.body.password, salt);
      updateData.password = hashedPassword;
    }

    const user = await User.findByIdAndUpdate(req.params.id, updateData, {
      new: true,
      runValidators: true,
    });

    res.status(200).json({
      status: "Success",
      data: {
        user,
      },
    });
  } catch (error) {
    res.status(500).json({
      status: "Error",
      message: error.message,
    });
  }
};

// @desc    Delete user
// @route   DELETE /api/users/:id
// @access  Private/Admin
const deleteUser = async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    res.status(204).json({
      status: "Success",
      data: null,
    });
  } catch (error) {
    res.status(500).json({
      status: "Error",
      message: error.message,
    });
  }
};

// @desc    Login user & get token
// @route   POST /api/users/login
// @access  Public
const loginUser = async (req, res) => {
  const { emailOrPhone, password } = req.body;

  if (!emailOrPhone || !password) {
    return res.status(400).json({
      status: "Error",
      message: "Please provide email/phone and password",
    });
  }

  try {
    // Check if input is email or phone
    const isEmail = emailOrPhone.includes("@");

    // Find user by either email or phone
    const user = await User.findOne(
      isEmail ? { email: emailOrPhone } : { phone: emailOrPhone }
    );

    if (!user) {
      return res.status(401).json({
        status: "Error",
        message: "Invalid email or password",
      });
    }

    // Check if password matches
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({
        status: "Error",
        message: "Invalid email or password",
      });
    }

    // Convert the Mongoose document to a plain JavaScript object
    const userObj = user.toObject();

    // Destructure the necessary properties
    const {
      firstName,
      lastName,
      email: userEmail,
      _id,
      role,
      idImage,
      phone,
      idNumber,
    } = userObj;

    // Create token
    const token = jwt.sign({ id: user._id, role }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRE,
    });

    res.status(200).json({
      status: "Success",
      token,
      data: {
        user: {
          firstName,
          lastName,
          email: userEmail,
          _id,
          role,
          idImage,
          phone,
          idNumber,
        },
      },
    });
  } catch (error) {
    res.status(500).json({
      status: "Error",
      message: error.message,
    });
  }
};

// @desc    Logout user / clear cookie
// @route   POST /api/users/logout
// @access  Public
const logoutUser = (req, res) => {
  res.cookie("jwt", "", {
    httpOnly: true,
    expires: new Date(0),
  });
  res
    .status(200)
    .json({ status: "Success", message: "Logged out successfully" });
};

// @desc    Handle contact form submission
// @route   POST /api/users/contact
// @access  Public
const contactMessage = async (req, res) => {
  try {
    const { firstName, lastName, email, phone, message, idNumber } = req.body;

    // Basic validation
    if (!firstName || !lastName || !email || !phone || !message || !idNumber) {
      return res.status(400).json({
        status: "Error",
        message: "All fields are required",
      });
    }

    // Send email
    await sendContactFormEmail({
      firstName,
      lastName,
      email,
      phone,
      message,
      idNumber,
    });

    // Send success response
    res.status(200).json({
      status: "Success",
      message: "Message sent successfully",
    });
  } catch (error) {
    res.status(500).json({
      status: "Error",
      message: error.message,
    });
  }
};

module.exports = {
  getAllusers,
  getUser,
  createUser,
  updateUser,
  deleteUser,
  loginUser,
  logoutUser,
  contactMessage,
};
