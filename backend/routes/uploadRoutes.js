const path = require("path");
const express = require("express");
const multer = require("multer");
const router = express.Router();
const { User } = require("../models/userModel");
const { protect } = require("../middleware/authMiddleware");
const iconv = require("iconv-lite");
const ffmpeg = require("fluent-ffmpeg");
const ffmpegInstaller = require("@ffmpeg-installer/ffmpeg");
ffmpeg.setFfmpegPath(ffmpegInstaller.path);

const getUploadFileName = (file) => {
  const originalName = iconv.decode(
    Buffer.from(file.originalname, "binary"),
    "utf8"
  );

  return `${Date.now()}-${path.parse(originalName).name}${path.extname(
    originalName
  )}`;
};

///// STORAGES /////
// Image storage configuration
const images = multer.diskStorage({
  destination: "./uploads/id-images",
  filename(req, file, cb) {
    cb(null, getUploadFileName(file));
  },
});

///// INSTANCES /////
// Image upload instance
const profileImageUpload = multer({
  storage: images,
  fileFilter: function (req, file, cb) {
    checkImageFileType(file, cb, "images");
  },
});

///// CHECK FILE TYPES /////
// Check image file type
function checkImageFileType(file, cb, storageType) {
  const filetypes = /pdf|jpeg|jpg|png|mp4|mov|avi/;
  const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype =
    /^(image\/(jpeg|jpg|png)|video\/(mp4|quicktime|x-msvideo))$/.test(
      file.mimetype
    );

  if (extname && mimetype) {
    return cb(null, true);
  } else {
    cb({
      message: `Allowed file types for ${storageType}: pdf, jpeg, jpg, png, mp4, mov, avi`,
    });
  }
}

// Check pdf file type
function checkPdfFileType(file, cb, storageType) {
  console.log("checkPdfFileType", file);

  const filetypes = /pdf/;
  const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = filetypes.test(file.mimetype);

  if (extname && mimetype) {
    return cb(null, true);
  } else {
    cb({
      message: `Allowed file types for ${storageType}: pdf, jpeg, jpg, png`,
    });
  }
}

// Function to compress video
const compressVideo = (inputPath, outputPath) => {
  return new Promise((resolve, reject) => {
    ffmpeg(inputPath)
      .videoCodec("libx264")
      .size("720x?") // Resize to 720p width, maintain aspect ratio
      .videoBitrate("1000k") // Reduce bitrate
      .outputOptions(["-crf 28"]) // Compression quality (23-28 is good range)
      .on("end", () => {
        // Delete original file after compression
        require("fs").unlink(inputPath, (err) => {
          if (err) console.error("Error deleting original video:", err);
        });
        resolve();
      })
      .on("error", (err) => reject(err))
      .save(outputPath);
  });
};

///// ROUTES /////
// Route for uploading to the profile images
router.post(
  "/id-images",
  protect,
  profileImageUpload.single("file"),
  async (req, res) => {
    try {
      const updatedUser = await User.findByIdAndUpdate(
        req.user.id,
        { $set: { idImage: req.file.path } },
        {
          new: true,
          runValidators: true,
        }
      );

      res.send({
        message: "File uploaded successfully to id-images",
        file: `${req.file.path}`,
        user: updatedUser,
      });
    } catch (error) {
      console.log("Error while saving id image", error);

      return res.status(500).json({ error });
    }
  }
);

module.exports = {
  router,
  profileImageUpload,
};
