import { NextFunction, Response } from "express";
import { AsyncHandler } from "../utils/async-handler";
import { TwoFaService } from "../services/2fa.service";
import { ApiError } from "../utils/api-error";
import { UserRequest } from "../types/user";
import { ApiResponse } from "../utils/api-response";

//? 2FA SETUP
export const setup2fa = AsyncHandler(
  async (req: UserRequest, res: Response, next: NextFunction) => {
    const user = req.user;

    if (!user?._id) {
      return next(ApiError.unauthorized("Unauthorized access"));
    }

    const { qr, codes } = await TwoFaService.setup2fa({
      userId: user._id
    });

    return ApiResponse.ok(res, "2FA setup successfully", {
      qr,
      codes: codes
    });
  }
);

//? 2FA VERIFY SETUP
export const verify2faSetup = AsyncHandler(
  async (req: UserRequest, res: Response, next: NextFunction) => {
    const user = req.user;

    if (!user?._id) {
      return next(ApiError.unauthorized("Unauthorized access"));
    }

    const { code } = req.body;

    if (!code) {
      return next(ApiError.badRequest("2FA code is required!"));
    }

    const otp = await TwoFaService.verify2faSetup({
      userId: user._id,
      code
    });

    return ApiResponse.ok(
      res,
      otp.message || "2FA setup verified successfully!"
    );
  }
);

//? 2FA STATUS
export const get2faStatus = AsyncHandler(
  async (req: UserRequest, res: Response, next: NextFunction) => {
    const user = req.user;

    if (!user?._id) {
      return next(ApiError.unauthorized("Unauthorized access"));
    }

    const status = await TwoFaService.get2faStatus({
      userId: user._id
    });

    return ApiResponse.ok(res, "2FA status", status);
  }
);

//? DISABLE 2FA
export const disable2fa = AsyncHandler(
  async (req: UserRequest, res: Response, next: NextFunction) => {
    const user = req.user;

    if (!user?._id) {
      return next(ApiError.unauthorized("Unauthorized access"));
    }

    await TwoFaService.disable2fa({
      userId: user._id
    });
    return ApiResponse.Success(res, "2FA disabled successfully!");
  }
);

//? REGENERATE BACKUP CODES
export const regenerateBackupCodes = AsyncHandler(
  async (req: UserRequest, res: Response, next: NextFunction) => {
    const user = req.user;

    if (!user?._id) {
      return next(ApiError.unauthorized("Unauthorized access"));
    }

    const { codes } = await TwoFaService.regenerateBackupCodes({
      userId: user._id
    });

    return ApiResponse.ok(res, "Backup codes regenerated successfully", {
      codes: codes
    });
  }
);

//? VERIFY BACKUP CODE
export const verifyBackupCode = AsyncHandler(
  async (req: UserRequest, res: Response, next: NextFunction) => {
    const user = req.user;

    if (!user?._id) {
      return next(ApiError.unauthorized("Unauthorized access"));
    }

    const { code } = req.body;
    if (!code) {
      return next(ApiError.badRequest("Code is required!"));
    }

    const otp = await TwoFaService.verifyBackupCode({
      userId: user._id,
      code
    });

    if (!otp) {
      return next(ApiError.server("Failed to verify OTP!"));
    }

    return ApiResponse.ok(res, otp.message || "OTP verified successfully!");
  }
);
