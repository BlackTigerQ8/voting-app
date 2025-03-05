const { User } = require("../models/userModel");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const {
  sendVerificationEmail,
  sendContactFormEmail,
} = require("../emailService");

// @desc    Get all users
// @route   GET /api/users
// @access  Private/Admin
const getAllusers = async (req, res) => {
  try {
    let query = {};
    const { role } = req.query;

    // If user is a coach, only return their assigned athletes
    if (req.user.role === "Coach") {
      query = {
        $or: [
          { _id: req.user._id }, // Include the coach themselves
          { role: "Athlete", coach: req.user._id }, // Include their athletes
        ],
      };
    } else if (req.user.role === "Admin") {
      // If a specific role is requested (e.g., for coach selection)
      if (req.query.role) {
        query.role = req.query.role;
      }
    } else if (req.user.role === "Athlete" || req.user.role === "Family") {
      // Allow Athletes and Family members to see only their own profile
      query = { _id: req.user._id };
    } else {
      // If user is neither Admin nor Coach, return unauthorized
      return res.status(403).json({
        status: "Error",
        message: "Not authorized to access user list",
      });
    }

    // If user is neither Admin nor Coach, return unauthorized
    // if (req.user.role !== "Admin" && req.user.role !== "Coach") {
    //   return res.status(403).json({
    //     status: "Error",
    //     message: "Not authorized to access user list",
    //   });
    // }

    const users = await User.find(query).populate(
      "coach",
      "firstName lastName _id role"
    );

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
    if (req.user.id !== req.params.id && req.user.role !== "Admin") {
      return res.status(403).json({
        status: "Error",
        message: "You do not have permission to access this user's data",
      });
    }

    res.status(200).json({
      stauts: "Success",
      data: { ...user._doc, imagePath: user.image },
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
    const uploadedFile = req.file;
    const filePath = uploadedFile ? uploadedFile.path : null;
    const newUser = await User.create({ ...req.body, image: filePath });

    // Generate verification token
    const verificationToken = newUser.createEmailVerificationToken();
    await newUser.save({ validateBeforeSave: false });

    // Create verification URL with explicit frontend URL
    if (!process.env.FRONTEND_URL) {
      console.error("FRONTEND_URL is not defined in environment variables");
    }

    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email/${verificationToken}`;
    console.log("Verification URL:", verificationUrl); // For debugging

    // Send verification email
    await sendVerificationEmail(newUser.email, verificationUrl);

    res.status(201).json({
      status: "Success",
      data: {
        user: newUser,
      },
    });
  } catch (error) {
    res.status(500).json({
      status: "Error",
      message: error.message,
    });
  }
};

// Verification endpoint
const verifyEmail = async (req, res) => {
  try {
    const hashedToken = crypto
      .createHash("sha256")
      .update(req.params.token)
      .digest("hex");

    const user = await User.findOne({
      emailVerificationToken: hashedToken,
      emailVerificationExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({
        status: "Error",
        message: "Token is invalid or has expired",
      });
    }

    // Update user verification status
    user.isEmailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpires = undefined;
    await user.save({ validateBeforeSave: false });

    res.status(200).json({
      status: "Success",
      message: "Email verified successfully",
    });
  } catch (error) {
    console.error("Verification error:", error);
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
    if (req.user.id !== req.params.id && req.user.role !== "Admin") {
      return res.status(403).json({
        status: "Error",
        message: "You do not have permission to access this user's data",
      });
    }

    const uploadedFile = req.file;
    const filePath = uploadedFile ? uploadedFile.path : null;

    // Prepare the updated data
    const updateData = req.file
      ? { ...req.body, image: filePath }
      : { ...req.body };

    // Handle coach field based on role
    if (updateData.role === "Athlete") {
      if (!updateData.coach) {
        return res.status(400).json({
          status: "Error",
          message: "Coach is required for athletes",
        });
      }
    } else {
      // If role is not Athlete, remove coach field
      updateData.coach = undefined;
    }

    // Check if password is included in the request body and hash it
    if (req.body.password) {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(req.body.password, salt);
      updateData.password = hashedPassword;
    }

    // Get the current user data
    const currentUser = await User.findById(req.params.id);

    // Check if email is being updated
    if (updateData.email && updateData.email !== currentUser.email) {
      // Set email verification status to false
      updateData.isEmailVerified = false;

      // Generate new verification token
      const verificationToken = crypto.randomBytes(32).toString("hex");
      updateData.emailVerificationToken = crypto
        .createHash("sha256")
        .update(verificationToken)
        .digest("hex");
      updateData.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

      // Create verification URL
      const verificationUrl = `${process.env.FRONTEND_URL}/verify-email/${verificationToken}`;

      // Send verification email
      await sendVerificationEmail(updateData.email, verificationUrl);
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
  const { email, password } = req.body;

  try {
    // Check for user email
    const user = await User.findOne({ email });

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
      image,
      phone,
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
          image,
          phone,
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
    const { firstName, lastName, email, phone, message } = req.body;

    // Basic validation
    if (!firstName || !lastName || !email || !phone || !message) {
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
  verifyEmail,
  contactMessage,
};
