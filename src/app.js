import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";

const app = express();

// Configure the CORS middleware to set frontendURI
app.use(
  cors({
    origin: process.env.CORS_ORIGIN,
    credential: true,
    methods: ["POST", "PATCH", "GET", "DELETE", "PUT"],
  })
);

// Configuration of middleware for handling the different data format
// JSON data from req.body
app.use(express.json({ limit: "16kb" }));
// URL based data from req.params
app.use(express.urlencoded({ extends: true, limit: "16kb" }));
// Static file data for storing in our server folder "public"
app.use(express.static("public"));
// Cookie Data for performing the CRUD operations through our server
app.use(cookieParser());

app.get("/", (req, res) => {
  return res.send("<h1>Console Busters blog app server is working fine✅</h1>");
});

// Import the routes
import userRouter from "./routes/user.routes.js";
import blogRouter from "./routes/blog.routes.js";

// Routes declaration middlewares
app.use("/api/v1/users", userRouter);
app.use("/api/v1/blogs", blogRouter);

// When any error occurs then we are calling custom error middleware for all routes
import { ErrorMiddleware } from "./middleware/error.middleware.js";
app.use(ErrorMiddleware);

export { app };
