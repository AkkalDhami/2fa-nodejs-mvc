import { NextFunction } from "express";
import User from "../models/user.model";
import { ApiError } from "../utils/api-error";
import { hashPassword, verifyPassword } from "../helpers/auth.helpers";
import { SigninUserType, SignupUserType } from "../validators/auth";
import {
  LOCK_TIME_MS,
  LOGIN_MAX_ATTEMPTS,
  REACTIVATION_AVAILABLE_AT,
  REFRESH_TOKEN_EXPIRY
} from "../constants/auth";
import {
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  verifyRefreshToken
} from "../utils/jwt";
import RefreshToken from "../models/refresh-token.model";
import { generateHashedToken } from "../helpers/token.helpers";
import { IUser } from "../types/user";
import mongoose, { Mongoose } from "mongoose";
import { OtpService } from "./otp.service";
import { deleteFileFromCloudinary } from "./cloudinary.service";
import { getRemainingTime } from "../utils/date";
import TwoFactorAuth from "../models/2fa.model";
import { TwoFaService } from "./2fa.service";

export type Context = {
  setAuthCookie?: (accessToken: string, refreshToken: string) => void;
};

export class AuthService {
  static async getUserById(userId: string) {
    return await User.findById(userId);
  }

  static async registerUser(
    next: NextFunction,
    user: Omit<SignupUserType, "confirmPassword">
  ) {
    const { name, email, password, role } = user;
    const existingUser = await User.findOne({ email }).select("+password");

    if (existingUser) {
      return next(ApiError.conflict("User with this email already exists"));
    }

    const hashedPassword = await hashPassword(password);

    const newUser = await User.create({
      name,
      email,
      password: hashedPassword,
      role
    });

    return newUser;
  }

  static async login(
    { email, password, code, recoveryCode }: SigninUserType,
    context: Context
  ) {
    const user = await User.findOne({ email }).select("+password");
    if (!user) {
      throw ApiError.unauthorized("Invalid credentials");
    }

    if (user.lockUntil && new Date() < user.lockUntil) {
      throw ApiError.forbidden(
        `Your account has been locked. Please try again after ${getRemainingTime(user.lockUntil).minutes} minutes and ${getRemainingTime(user.lockUntil).seconds} seconds.`
      );
    }

    const isPasswordValid = await verifyPassword(password, user.password || "");
    if (!isPasswordValid) {
      let lockUntil = null;

      let newAttempts = user.failedLoginAttempts + 1;

      if (newAttempts >= LOGIN_MAX_ATTEMPTS) {
        lockUntil = new Date(Date.now() + LOCK_TIME_MS);
      }

      await User.updateOne(
        {
          _id: user._id
        },
        {
          failedLoginAttempts: newAttempts,
          lockUntil
        }
      );
      throw ApiError.unauthorized("Invalid credentials");
    }

    const twoFactor = await TwoFactorAuth.findOne({ userId: user._id });
    if (twoFactor?.enabled && (!code && !recoveryCode)) {
      throw ApiError.unauthorized("Please verify your 2FA");
    }

    if (twoFactor?.enabled && code && recoveryCode) {
      throw ApiError.unauthorized(
        "Please provide either 2FA code or recovery code"
      );
    }

    if (twoFactor?.enabled && code) {
      const isOtpValid = await TwoFaService.verifyOtpDuringLogin({
        userId: user._id.toString(),
        code
      });

      if (!isOtpValid.message) {
        throw ApiError.unauthorized("Invalid 2FA code");
      }
    }

    if (twoFactor?.enabled && recoveryCode) {
      const isRecoveryCodeValid = await TwoFaService.verifyBackupCode({
        userId: user._id.toString(),
        code: recoveryCode
      });

      if (!isRecoveryCodeValid.message) {
        throw ApiError.unauthorized("Invalid recovery code");
      }
    }

    await User.updateOne(
      {
        _id: user._id
      },
      {
        failedLoginAttempts: 0,
        lockUntil: null
      }
    );

    const accessToken = await this.handleToken(
      {
        _id: user._id.toString(),
        isEmailVerified: user.isEmailVerified,
        role: user.role
      },
      context
    );

    return accessToken;
  }

  static async handleToken(
    user: Pick<IUser, "isEmailVerified" | "_id" | "role">,
    context: Context
  ) {
    if (!user.isEmailVerified) {
      await User.updateOne(
        { _id: user._id },
        { $set: { isEmailVerified: true } }
      );
    }

    const accessToken = generateAccessToken({
      _id: user._id,
      role: user.role
    });

    const refreshToken = generateRefreshToken(user._id);

    const hashedRefreshToken = generateHashedToken(refreshToken);

    await RefreshToken.create({
      userId: new mongoose.Types.ObjectId(user._id),
      tokenHash: hashedRefreshToken,
      expiresAt: new Date(Date.now() + REFRESH_TOKEN_EXPIRY)
    });

    context.setAuthCookie && context.setAuthCookie(accessToken, refreshToken);

    await User.updateOne(
      { _id: user._id },
      {
        $set: { lastLogin: new Date(), failedLoginAttempts: 0 },
        $unset: { lockUntil: 1 }
      }
    );
    return accessToken;
  }

  static async getUserProfile(userId: string): Promise<IUser> {
    const [profile]: IUser[] = await User.aggregate([
      {
        $match: { _id: new mongoose.Types.ObjectId(userId) }
      },
      {
        $lookup: {
          from: "2fas",
          localField: "_id",
          foreignField: "userId",
          as: "twoFactor"
        }
      },
      {
        $unwind: {
          path: "$twoFactor",
          preserveNullAndEmptyArrays: true
        }
      },
      {
        $project: {
          name: 1,
          email: 1,
          role: 1,
          avatar: 1,
          isEmailVerified: 1,
          createdAt: 1,
          updatedAt: 1,
          lastLogin: 1,
          twoFactor: {
            enabled: { $ifNull: ["$twoFactor.enabled", false] },
            enabledAt: "$twoFactor.enabledAt",
            lastUsedAt: "$twoFactor.lastUsedAt",

            remainingBackupCodes: {
              $size: "$twoFactor.backupCodes"
            }
          }
        }
      }
    ]);
    return profile;
  }

  static async refreshTokens(
    next: NextFunction,
    accessToken: string | null,
    refreshToken: string
  ) {
    if (!refreshToken) {
      return next(ApiError.unauthorized("Unauthorized, please login."));
    }

    const decodedRefresh = verifyRefreshToken(refreshToken);
    if (!decodedRefresh?.userId) {
      return next(ApiError.unauthorized("Invalid refresh token."));
    }

    const refreshTokenHash = generateHashedToken(refreshToken);

    const storedToken = await RefreshToken.findOne({
      userId: decodedRefresh.userId,
      tokenHash: refreshTokenHash
    });

    // Reuse detection
    if (!storedToken) {
      await RefreshToken.updateMany(
        { userId: decodedRefresh.userId },
        { isRevoked: true, revokedAt: new Date() }
      );
      return next(
        ApiError.unauthorized("Token reuse detected. Please login again.")
      );
    }

    if (storedToken.isRevoked) {
      return next(ApiError.unauthorized("Refresh token revoked."));
    }

    if (storedToken.expiresAt < new Date()) {
      return next(ApiError.unauthorized("Refresh token expired."));
    }

    if (accessToken) {
      const decodedAccess = verifyAccessToken(accessToken);
      if (decodedAccess._id !== decodedRefresh.userId) {
        return next(ApiError.unauthorized("Token mismatch."));
      }
    }

    const user = await User.findById(decodedRefresh.userId);
    if (!user) {
      return next(ApiError.unauthorized("User not found."));
    }

    const newAccessToken = generateAccessToken({
      _id: user._id.toString(),
      role: user.role
    });

    const newRefreshToken = generateRefreshToken(user._id.toString());
    const newRefreshTokenHash = generateHashedToken(newRefreshToken);

    //? Rotate token
    storedToken.isRevoked = true;
    storedToken.revokedAt = new Date();
    storedToken.replacedByTokenHash = newRefreshTokenHash;
    await storedToken.save();

    await RefreshToken.create({
      userId: user._id,
      tokenHash: newRefreshTokenHash,
      expiresAt: new Date(Date.now() + REFRESH_TOKEN_EXPIRY)
    });

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken
    };
  }

  static async logoutUser(userId: string) {
    return await RefreshToken.updateMany(
      { userId },
      { isRevoked: true, revokedAt: new Date() }
    );
  }

  static async forgotPassword(next: NextFunction, email: string) {
    const user = await User.findOne({ email });

    if (!user) {
      return next(
        ApiError.badRequest("If this email is registered, check your inbox.")
      );
    }

    const result = await OtpService.sendOtp(next, {
      email,
      otpType: "password-reset",
      subject: "Password Reset"
    });

    if (!result) {
      return next(ApiError.server("Failed to send otp!"));
    }

    return result;
  }

  static async resetPassword(
    next: NextFunction,
    email: string,
    newPassword: string
  ) {
    const user = await User.findOne({ email }).select("+password");

    if (!user) {
      return next(ApiError.unauthorized("Unauthorized access"));
    }

    if (user.lockUntil && user.lockUntil.getTime() > Date.now()) {
      const remainingTime = getRemainingTime(user.lockUntil);

      return next(
        ApiError.forbidden(
          `Your account has been locked. Please try again after ${remainingTime.minutes} minutes and ${remainingTime.seconds} seconds.`
        )
      );
    }

    if (user.failedLoginAttempts >= LOGIN_MAX_ATTEMPTS && user.lockUntil) {
      return next(
        ApiError.forbidden(
          `You have exceeded the maximum number of login attempts. Please try again after ${getRemainingTime(user.lockUntil).minutes} minutes and ${getRemainingTime(user.lockUntil).seconds} seconds.`
        )
      );
    }

    if (!user.isEmailVerified) {
      return next(ApiError.unauthorized("Please verify your email first."));
    }

    const oldPassword = user.password;

    const isOldPassword = await verifyPassword(
      newPassword,
      oldPassword as string
    );

    if (isOldPassword) {
      return next(ApiError.badRequest("New password should be different!"));
    }

    const hashedPassword = await hashPassword(newPassword);
    await User.updateOne(
      { email },
      {
        $set: {
          password: hashedPassword,
          isEmailVerified: true
        }
      }
    );
    return { message: "Password reset successfully!" };
  }

  static async changePassword(
    next: NextFunction,
    {
      newPassword,
      oldPassword,
      userId
    }: { userId: string; newPassword: string; oldPassword: string }
  ) {
    const user = await User.findById(userId).select("+password");
    if (!user) {
      return next(ApiError.unauthorized("Unauthorized access"));
    }

    if (!user.isEmailVerified) {
      return next(ApiError.unauthorized("Please verify your email first."));
    }

    const isOldPassword = await verifyPassword(
      oldPassword,
      user.password || ""
    );

    if (!isOldPassword) {
      return next(ApiError.unauthorized("Invalid credentials"));
    }

    if (newPassword === oldPassword) {
      return next(ApiError.badRequest("New password should be different!"));
    }

    const hashedPassword = await hashPassword(newPassword);
    await User.updateOne(
      { _id: userId },
      {
        $set: {
          password: hashedPassword
        }
      }
    );
    return { message: "Password changed successfully. Please login again!" };
  }

  static async deleteOrDeactiveAccount(
    next: NextFunction,
    userId: string,
    type: "soft" | "hard"
  ) {
    const user = await User.findById(userId);
    if (!user) {
      return next(ApiError.unauthorized("Unauthorized access"));
    }

    if (type === "soft") {
      user.isDeleted = true;
      user.deletedAt = new Date();
      user.reActivateAvailableAt = new Date(
        Date.now() + REACTIVATION_AVAILABLE_AT
      );
      await user.save();
    } else if (type === "hard") {
      if (user?.avatar?.public_id) {
        await deleteFileFromCloudinary([user.avatar.public_id]);
      }
      await User.findOneAndDelete({ _id: userId });
      await user.save();
    }
  }

  static async reactivateAccount(next: NextFunction, userId: string) {
    const user = await User.findById(userId);
    if (!user) {
      return next(ApiError.unauthorized("Unauthorized access"));
    }

    if (user.lockUntil && user.lockUntil.getTime() > Date.now()) {
      const remainingTime = getRemainingTime(user.lockUntil);

      return next(
        ApiError.forbidden(
          `Your account has been locked. Please try again after ${remainingTime.minutes} minutes and ${remainingTime.seconds} seconds.`
        )
      );
    }

    if (!user?.isDeleted || !user?.deletedAt) {
      return next(ApiError.badRequest("Your account is already active!"));
    }

    if (
      user?.reActivateAvailableAt &&
      new Date(user?.reActivateAvailableAt) > new Date()
    ) {
      return next(
        ApiError.forbidden(
          `Your account has been locked. Please try again after ${Math.ceil(
            (user.reActivateAvailableAt.getTime() - Date.now()) / (1000 * 60)
          )} minutes.`
        )
      );
    }

    await User.findOneAndUpdate(
      { _id: userId },
      {
        $set: {
          isDeleted: false,
          deletedAt: null,
          reActivateAvailableAt: null
        }
      },
      { new: true }
    );

    await user.save();
  }
}
