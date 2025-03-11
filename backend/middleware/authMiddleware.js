const jwt = require("jsonwebtoken");
const { User } = require("../models/userModel");

const protect = async (req, res, next) => {
  let token = req.headers?.authorization || "";

  if (token && token.startsWith("Bearer")) {
    try {
      // Get token from header
      token = req.headers.authorization.split(" ")[1];

      // Verify token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      // Get user from the token
      req.user = await User.findById(decoded.id).select("-password");

      if (!req.user) {
        return res.status(401).json({
          status: "Error",
          message: "User not found",
        });
      }

      return next();

      // Proceed to the next middleware
    } catch (error) {
      console.error(error);
      return res.status(401).json({
        status: "Error",
        message: "Not authorized to access this route error",
      });
    }
  }

  // If no token is provided
  if (!token) {
    return res.status(401).json({
      status: "Error",
      message: "Not authorized to access this route",
    });
  }
};

const restrictTo = (...roles) => {
  return (req, res, next) => {
    // Check if the user's role is in the allowed roles array
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        status: "Error",
        message: "You do not have permission to perform this action",
      });
    }

    // If role matches, proceed to the next middleware
    next();
  };
};

module.exports = {
  protect,
  restrictTo,
};
