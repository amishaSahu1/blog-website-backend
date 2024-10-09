import mongoose from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import validator from "validator";
import crypto from "crypto";
import { AvailableUserRoles, UserRolesEnum } from "../../constants.js";

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: [true, "Please enter your username"],
      unique: true,
      lowercase: true,
      trim: true,
    },
    email: {
      type: String,
      required: [true, "Please enter your email"],
      unique: true,
      lowercase: true,
      trim: true,
      validate: validator.isEmail,
    },
    fullName: {
      type: String,
      required: [true, "Please enter your fullname"],
      trim: true,
      index: true,
    },
    password: {
      type: String,
      required: [true, "Please enter your password"],
      minLength: [6, "Password must be at least 6 characters"],
    },
    role: {
      type: String,
      enum: AvailableUserRoles,
      default: UserRolesEnum.USER,
      required: true,
      lowercase: true,
    },
    blogs: [
      {
        type: mongoose.Types.ObjectId,
        ref: "Blogs",
      },
    ],
    refreshToken: {
      type: String,
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    resetPasswordToken: String,
    resetPasswordTokenExpiry: Date,
    otp: String,
    otpExpiry: Date,
  },
  { timestamps: true }
);

// Use mongoose hook middleware to hash the input password just before save in database
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  this.password = await bcrypt.hash(this.password, 10);
  next();
});

// Use our custom method to check the input password is correct or not
userSchema.methods.isPasswordCorrect = async function (password) {
  return await bcrypt.compare(password, this.password); // true or false
};

// Use our custom method to generate the ACCESS TOKEN
userSchema.methods.generateAccessToken = function () {
  return jwt.sign(
    {
      _id: this._id,
      email: this.email,
      username: this.username,
      fullName: this.fullName,
    },
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
    }
  );
};

// Use our custom method to generate the REFRESH TOKEN
userSchema.methods.generateRefreshToken = function () {
  return jwt.sign(
    {
      _id: this._id,
    },
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
    }
  );
};

// Use our custom method "getResetPasswordToken" to generate the reset password token
userSchema.methods.getResetPasswordToken = function () {
  // Step 1: Generate Random Token
  const resetToken = crypto.randomBytes(20).toString("hex");

  // Step 2: Hash Token
  this.resetPasswordToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  // Step 3: Set Reset Password Expiry
  this.resetPasswordTokenExpiry = Date.now() + 15 * 60 * 1000; // 15 minutes

  // Return Reset Token
  return resetToken;
};

// Use our custom method "generateRandomOTPToken" to generate the random OTP
userSchema.methods.generateRandomOTPToken = function () {
  // Step 1: Generate 6 digit random OTP
  const randomOTP = Math.floor(100000 + Math.random() * 900000).toString();

  // Step 2: Hashed Random OTP
  this.otp = crypto.createHash("sha256").update(randomOTP).digest("hex");

  // Step 3: Set OTP Expiry
  this.otpExpiry = Date.now() + 15 * 60 * 1000; // 15 minutes

  // Return Random OTP
  return randomOTP;
};

export const User = mongoose.model("Users", userSchema);
