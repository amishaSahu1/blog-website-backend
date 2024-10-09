import mongoose from "mongoose";
import { AvailableBlogCategory } from "../../constants.js";

const blogSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: [true, "Please enter blog title"],
      trim: true,
    },
    slug: {
      type: String,
      trim: true,
      default: "",
    },
    description: {
      type: String,
      required: [true, "Please enter blog description"],
      trim: true,
    },
    content: {
      type: String,
      required: [true, "Please enter blog content"],
    },
    keywords: {
      type: String,
      default: "",
    },
    owner: {
      type: mongoose.Types.ObjectId,
      ref: "Users",
    },
    isPublished: {
      type: Boolean,
      default: false,
    },
    category: {
      type: String,
      enum: AvailableBlogCategory,
      required: true,
      lowercase: true,
    },
  },
  { timestamps: true }
);

export const Blog = mongoose.model("Blogs", blogSchema);
