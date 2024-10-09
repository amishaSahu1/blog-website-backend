import express from "express";
import {
  registerUser,
  forgotPassword,
  resetPassword,
  loginUser,
  getUserProfile,
  logoutUser,
  refreshAccessToken,
  updateUserProfile,
  deleteUserProfile,
  verifyOTP,
} from "../controllers/user.controller.js";
import { verifyJWT } from "../middleware/auth.middleware.js";

const router = express.Router();

// Public Routes For User
router.route("/register").post(registerUser);
router.route("/login").post(loginUser);
router.route("/forgot-password").post(forgotPassword);
router.route("/reset-password/:resetToken").post(resetPassword);
router.route("/verify-otp").post(verifyOTP);

// Secure Routes For Profile Management System
router.route("/profile").get(verifyJWT, getUserProfile);
router.route("/profile/logout").post(verifyJWT, logoutUser);
router.route("/profile/update").patch(verifyJWT, updateUserProfile);
router.route("/profile/delete").delete(verifyJWT, deleteUserProfile);
router.route("/profile/refresh").post(refreshAccessToken);

export default router;
