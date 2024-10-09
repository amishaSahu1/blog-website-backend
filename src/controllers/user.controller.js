import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/apiError.js";
import { User } from "../models/auth/user.model.js";
import { ApiResponse } from "../utils/apiResponse.js";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import {
  forgotPasswordMailgenContent,
  OTPMailgenContent,
  sendEmail,
} from "../utils/mail.js";

//? Method to generate the access and refresh token
const generateAccessAndRefreshTokens = async (userId) => {
  try {
    const user = await User.findOne(userId);
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    // Now add new refresh token to the exist user entry in DB
    user.refreshToken = refreshToken;
    // Save the exist user without validation
    await user.save({ validateBeforeSave: false });
    // Now returning both access and refresh token to client
    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(
      500,
      "Something went wrong while generating refresh and access token"
    );
  }
};

// Public Controllers
const verifyOTP = asyncHandler(async (req, res) => {
  // Step 1: get OTP from user
  const { randomOTP } = req.body;

  if (!randomOTP) {
    throw new ApiError("OTP is required");
  }

  // Step 2: hash random OTP and verify it
  const otp = crypto.createHash("sha256").update(randomOTP).digest("hex");

  const user = await User.findOne({
    otp,
    otpExpiry: {
      $gt: Date.now(),
    },
  }).select("-password -refreshToken");

  if (!user) {
    throw new ApiError(401, "OTP has been expired or invalid.");
  }

  // Step 3: generate the access and refresh token
  const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
    user?._id
  );

  // Step 4: update the otp, expiry, and isVerified
  user.otp = undefined;
  user.otpExpiry = undefined;
  user.isVerified = true;
  await user.save({ validateBeforeSave: false });

  // Step 5: send cookies with returning the response
  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        {
          accessToken,
          refreshToken,
        },
        "User logged in successfully"
      )
    );
});

const registerUser = asyncHandler(async (req, res) => {
  // Step 1: get user details from frontend
  const { fullName, email, username, password, confirmPassword } = req.body;

  // Step 2: validation for not empty fields
  if (
    [fullName, email, username, password, confirmPassword].some(
      (field) => field?.trim() === ""
    )
  ) {
    throw new ApiError(400, "All fields are required");
  }

  if (password !== confirmPassword) {
    throw new ApiError(400, "Password does not match");
  }

  // Step 3: check if user already exist or not using username or email
  const existedUser = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (existedUser) {
    throw new ApiError(409, "User with email or username already exists");
  }

  // Step 4: create user object - create a user entry in DB
  const user = await User.create({
    username: username.toLowerCase(),
    email,
    fullName,
    password,
  });

  // Step 5: remove password and refresh token from response
  const createUser = await User.findOne(user._id).select(
    "-password -refreshToken"
  );
  if (!createUser) {
    throw new ApiError(500, "Something went wrong while registering the user");
  }

  // TODO: Generate and send OTP
  const randomOTP = createUser.generateRandomOTPToken();
  createUser.save({ validateBeforeSave: false });

  // send OTP
  const response = await sendEmail({
    email: createUser?.email,
    subject: "OTP from Vecros Blog Application",
    mailgenContent: OTPMailgenContent(createUser.username, randomOTP),
  });

  // check message sent or not
  if (!response) {
    createUser.otp = undefined;
    createUser.otpExpiry = undefined;
    await createUser.save({ validateBeforeSave: false });
    throw new ApiError(404, "Error sending email");
  }

  // Step 6: return the response to the client
  return res
    .status(201)
    .json(
      new ApiResponse(
        201,
        {},
        "Profile created successfully & OTP has been sent to your registered email."
      )
    );
});

const loginUser = asyncHandler(async (req, res) => {
  // Step 1: get user details from frontend
  const { email, username, password } = req.body;

  // Step 2: validation for not empty fields
  if (!username && !email) {
    throw new ApiError(400, "username or email is required");
  }

  // Step 3: find the exist user based on username or email
  const user = await User.findOne({
    $or: [{ username }, { email }],
  });

  // Step 4: check user does exist or not
  if (!user) {
    throw new ApiError(404, "User does not exist");
  }

  // Todo: Validate the email is verified or not
  if (!user.isVerified) {
    // Action 1: Generate and send OTP
    const randomOTP = user.generateRandomOTPToken();
    user.save({ validateBeforeSave: false });

    // send OTP
    const response = await sendEmail({
      email: user?.email,
      subject: "OTP from Vecros Blog Application",
      mailgenContent: OTPMailgenContent(user.username, randomOTP),
    });

    // check message sent or not
    if (!response) {
      user.otp = undefined;
      user.otpExpiry = undefined;
      await user.save({ validateBeforeSave: false });
      throw new ApiError(404, "Error sending email");
    }

    // Action 2: Save input password as new password
    user.password = password;
    await user.save({ validateBeforeSave: false });

    return res
      .status(200)
      .json(
        new ApiResponse(200, {}, "OTP has been sent to your registered email.")
      );
  }

  // Step 5: verify the input password from DB password
  const isPasswordValid = await user.isPasswordCorrect(password);
  if (!isPasswordValid) {
    throw new ApiError(401, "Invalid user credentials");
  }

  // Step 6: generate the access and refresh token
  const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
    user._id
  );

  // Step 7: remove password and refresh token from response
  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  // Step 8: send response to the user with cookies
  const options = {
    // This option makes not modifiable cookies from the client side
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        {
          accessToken,
          refreshToken,
        },
        "User logged in successfully"
      )
    );
});

const forgotPassword = asyncHandler(async (req, res) => {
  // Step 1: get email from user and check it is exist in DB or not
  const { email } = req.body;

  if (!email) {
    throw new ApiError(400, "email is required");
  }

  const user = await User.findOne({ email });
  if (!user) {
    throw new ApiError(404, "Invalid registered email or user does not exist");
  }

  // Todo: Validate the email is verified or not
  if (!user.isVerified) {
    throw new ApiError(400, "First verify your email id through login.");
  }

  // Step 2: generate reset token and save user
  const resetToken = await user.getResetPasswordToken();
  await user.save({ validateBeforeSave: false });

  // Step 3: create reset new password link and send message
  const verificationUrl = `${process.env.CORS_ORIGIN}/reset-password/${resetToken}`;

  // Step 4: send reset password link to the user's email
  const response = await sendEmail({
    email: user?.email,
    subject: "Password reset request",
    mailgenContent: forgotPasswordMailgenContent(
      user.username,
      verificationUrl
    ),
  });

  // Step 5: check message sent or not
  if (!response) {
    user.resetPasswordToken = undefined;
    user.resetPasswordTokenExpiry = undefined;
    await user.save({ validateBeforeSave: false });
    throw ApiError(404, "Error sending email");
  }

  // Step 6: return response to the user
  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        {},
        "Reset password link sent successfully to your registered email."
      )
    );
});

const resetPassword = asyncHandler(async (req, res) => {
  // Step 1: get reset token from reset password link
  const { resetToken } = req.params;

  // Step 2: hash reset token to check with DB reset token
  const resetPasswordToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  const user = await User.findOne({
    resetPasswordToken,
    resetPasswordTokenExpiry: {
      $gt: Date.now(),
    },
  }).select("-password -refreshToken");

  if (!user) {
    throw new ApiError(
      401,
      "Reset password token is invalid or has been expired"
    );
  }

  // Step 3: get new password from user
  const { password, confirmPassword } = req.body;
  if (password && password.length < 7) {
    throw new ApiError(400, "Password must be at least 6 characters");
  }
  if (!password || !confirmPassword) {
    throw new ApiError(400, "Both fields are required");
  }
  if (password !== confirmPassword) {
    throw new ApiError(400, "Password does not match");
  }

  // Step 3: set the new password and update the token and expiry
  user.password = password;
  user.resetPasswordToken = undefined;
  user.resetPasswordTokenExpiry = undefined;
  await user.save({ validateBeforeSave: false });

  // Step 4: return response to the user
  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password change successfully."));
});

// Protected Controllers
const logoutUser = asyncHandler(async (req, res) => {
  // Step 1: veryJWT to get the user's id
  const userID = req.user._id;

  // Step 2: update the exist refresh token in DB
  await User.findByIdAndUpdate(
    userID,
    {
      $set: {
        refreshToken: undefined,
      },
    },
    {
      // This is used to new updated data like refreshToken: undefined
      new: true,
    }
  );

  // Step 3: clear the cookies and return the response to the client
  const options = {
    // This option makes not modifiable cookies from the client side
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged out"));
});

const getUserProfile = asyncHandler(async (req, res) => {
  // Step 1: veryJWT to get the user's id
  const userID = req.user?._id;

  // Step 2: get user from DB via userID & remove sensitive information from user
  const user = await User.findById(userID).select("-password -refreshToken");

  // Step 3: return response to the user
  return res
    .status(200)
    .json(new ApiResponse(200, { user: user }, "Profile fetched successfully"));
});

const updateUserProfile = asyncHandler(async (req, res) => {
  // Step 1: get email, username and fullname from user
  const { fullName, email, username } = req.body;
  if (!fullName || !email || !username) {
    throw new ApiError(400, "All fields are required");
  }

  // Step 2: get user id to update the modified fields in DB
  const userID = req.user?._id;
  const user = await User.findByIdAndUpdate(
    userID,
    {
      $set: {
        fullName,
        email,
        username,
      },
    },
    { new: true }
  ).select("-password -refreshToken");

  // Step 3: return response to the user
  return res
    .status(200)
    .json(new ApiResponse(200, { user: user }, "Profile updated successfully"));
});

const deleteUserProfile = asyncHandler(async (req, res) => {
  // Step 1: veryJWT to get the user's id
  const userID = req.user?._id;

  // Step 2: delete user from DB
  await User.deleteOne({ _id: userID });

  // Step 3: clear the cookies and return the response to the client
  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "Profile deleted successfully"));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
  // Step 1: get refresh token from cookies and validate
  const incomingRefreshToken =
    req.cookies.refreshToken || req.body.refreshToken;

  if (!incomingRefreshToken) {
    throw new ApiError(401, "unauthorized request");
  }

  try {
    // Step 2: decode the incomingRefreshToken
    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );

    // Step 3: find user from db for getting the old refreshToken to compare with incomingRefreshToken
    const user = await User.findById(decodedToken?._id);

    if (!user) {
      throw new ApiError(401, "Invalid refresh token");
    }

    // Step 4: compare old refreshToken with incomingRefreshToken
    if (incomingRefreshToken !== user?.refreshToken) {
      throw new ApiError(401, "Refresh token is expired or used");
    }

    // Step 5: generate new accessToken and refreshToken
    const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
      user._id
    );

    // Step 6: return response with cookies
    const options = {
      httpOnly: true,
      secure: true,
    };

    return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", refreshToken, options)
      .json(
        new ApiResponse(
          200,
          { accessToken, refreshToken },
          "Access token refreshed"
        )
      );
  } catch (error) {
    throw new ApiError(401, error?.message || "Invalid refresh token");
  }
});

export {
  registerUser,
  loginUser,
  logoutUser,
  refreshAccessToken,
  forgotPassword,
  resetPassword,
  getUserProfile,
  updateUserProfile,
  deleteUserProfile,
  verifyOTP,
};
