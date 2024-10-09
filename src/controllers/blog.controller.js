import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/apiError.js";
import { ApiResponse } from "../utils/apiResponse.js";
import { Blog } from "../models/blogs/blog.model.js";
import { User } from "../models/auth/user.model.js";
import { ApiFeatures } from "../utils/apiFeatures.js";

//? Create the slug for each post
const generateSlug = (title) => {
  if (title && typeof title === "string") {
    return title
      .trim()
      .toLowerCase()
      .replace(/[^a-zA-Z\d\s]+/g, "-")
      .replace(/\s/g, "-");
  }
  return "";
};

// Blog Management Controllers
const createBlog = asyncHandler(async (req, res) => {
  // Step 1: Get blog data from user
  const { title, description, content, category, isPublished, keywords } =
    req.body;
  const owner = req.user?._id;

  // Step 2: Validation for not empty fields
  if (
    [title, description, content, category].some(
      (field) => field?.trim() === ""
    )
  ) {
    throw new ApiError(400, "All fields are required");
  }

  // Todo: Create slug using title
  const slug = generateSlug(title);

  // Step 3: Create the new blog
  const blog = await Blog.create({
    title,
    description,
    content,
    category,
    owner,
    isPublished: isPublished || false,
    slug: slug || "",
    keywords: keywords || "",
  });

  if (!blog) {
    throw new ApiError(409, "Something went wrong while creating blog.");
  }

  // Step 4: Push blog into the user's blogs field
  const user = await User.findOne({ _id: owner });
  user.blogs.push(blog._id);
  await user.save({ validateBeforeSave: false });

  // Step 5: Return response to the user
  return res
    .status(201)
    .json(new ApiResponse(201, { blog: blog }, "Blog created successfully"));
});

const updateBlog = asyncHandler(async (req, res) => {
  // Step 1: Get blog data from user
  const { title, description, content, category, isPublished, keywords } =
    req.body;
  const blogId = req.params?.id;

  // Step 2: Validation for not empty fields
  if (
    [title, description, content, category].some(
      (field) => field?.trim() === ""
    )
  ) {
    throw new ApiError(400, "All fields are required");
  }

  // Todo: Create slug using title
  const slug = generateSlug(title);

  // Step 3: Find and update the blog
  const updatedBlog = await Blog.findByIdAndUpdate(
    blogId,
    {
      $set: {
        title,
        description,
        content,
        category,
        isPublished,
        slug,
        keywords,
      },
    },
    { new: true }
  );

  if (!updatedBlog) {
    throw new ApiError(404, "Blog not found");
  }

  // Step 4: Return response to the user
  return res
    .status(200)
    .json(
      new ApiResponse(200, { blog: updatedBlog }, "Blog updated successfully")
    );
});

const deleteBlog = asyncHandler(async (req, res) => {
  // Step 1: Find and delete the blog from db
  const blogId = req.params?.id;

  const deletedBlog = await Blog.findByIdAndDelete(blogId);

  if (!deletedBlog) {
    throw new ApiError(404, "Blog not found");
  }

  // Step 2: Remove deleted blog from user's blogs field
  const userId = deletedBlog.owner;
  await User.findByIdAndUpdate(userId, {
    $pull: { blogs: blogId },
  });

  // Step 3: Return response to the user
  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Blog deleted successfully"));
});

const fetchBlog = asyncHandler(async (req, res) => {
  const blogId = req.params?.id;
  const blog = await Blog.findById(blogId);

  if (!blog) {
    throw new ApiError(404, "Blog not found");
  }

  return res
    .status(200)
    .json(new ApiResponse(200, { blog: blog }, "Blog fetched successfully"));
});

const fetchAllBlog = asyncHandler(async (req, res) => {
  // Step 1: Find the user to count the blogs count
  const owner = req.user?._id;
  const user = await User.findById(owner);
  if (!user) {
    throw new ApiError(404, "User not found");
  }

  // Step 2: Apply filtering for isPublished and category
  const apiFeatures = new ApiFeatures(Blog.find({ owner }), req.query)
    .filterBlogs()
    .paginate(10);

  // Step 3: Get all blogs from the user's blogs field
  const blogs = await apiFeatures.queryObject;

  // Calculation to manage the pagination from client side
  const resultLimitPerPage = 10;
  const blogsCount = user.blogs.length;
  const currentPage = Number(req.query?.page) || 1;
  const totalPages = Math.ceil(blogsCount / resultLimitPerPage);

  // Step 4: Return response to the user
  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        { blogs, currentPage, totalPages, blogsCount },
        "Blogs fetched successfully"
      )
    );
});

// Public Controller
const fetchAllBlogPublic = asyncHandler(async (req, res) => {
  // Step 1: Apply filtering for category
  const apiFeatures = new ApiFeatures(Blog.find(), req.query)
    .filterBlogs()
    .paginate(10);

  // Step 2: Get all filtered and paginated blogs
  const blogs = await apiFeatures.queryObject.populate(
    "owner",
    "username -_id"
  );

  // Calculation to manage the pagination from client side
  const resultLimitPerPage = 10;
  const blogsCount = await Blog.countDocuments();
  const currentPage = Number(req.query?.page) || 1;
  const totalPages = Math.ceil(blogsCount / resultLimitPerPage);

  // Step 3: Return response to the user
  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        { blogs, currentPage, totalPages, blogsCount },
        "Blogs fetched successfully"
      )
    );
});

export {
  createBlog,
  updateBlog,
  deleteBlog,
  fetchBlog,
  fetchAllBlog,
  fetchAllBlogPublic,
};
