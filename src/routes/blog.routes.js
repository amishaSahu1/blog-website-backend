import express from "express";
import { verifyJWT } from "../middleware/auth.middleware.js";
import {
  createBlog,
  deleteBlog,
  fetchAllBlog,
  fetchAllBlogPublic,
  fetchBlog,
  updateBlog,
} from "../controllers/blog.controller.js";

const router = express.Router();

// Blog Management System

// Protected Routes
router.route("/create").post(verifyJWT, createBlog);
router.route("/update/:id").patch(verifyJWT, updateBlog);
router.route("/delete/:id").delete(verifyJWT, deleteBlog);
router.route("/all").get(verifyJWT, fetchAllBlog);
router.route("/fetch/:id").get(fetchBlog);
 
// Public Routes
router.route("/public/all").get(fetchAllBlogPublic);

export default router;
