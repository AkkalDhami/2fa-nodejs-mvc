import TwoFactorAuth from "../models/2fa.model";
import { ApiError } from "../utils/api-error";
import {
  generateBackupCodes,
  generateHashedToken
} from "../helpers/token.helpers";
import User from "../models/user.model";
import {
  BACKUP_CODE_LENGTH,
  BACKUP_CODES_COUNT,
  LOCK_TIME_MS,
  LOGIN_MAX_ATTEMPTS
} from "../constants/auth";
import {
  generateQrCode,
  generateTOTP,
  verifyTOTP
} from "../helpers/2fa.helpers";

export class TwoFaService {
  static async setup2fa({ userId }: { userId: string }) {
    let twoFactor = await TwoFactorAuth.findOne({ userId });

    const user = await User.findById(userId);

    if (!user) {
      throw ApiError.unauthorized("Unauthorized access");
    }

    const totp = generateTOTP({ email: user.email });
    const otpauthUrl = totp.toString();
    const secretBase32 = totp.secret.base32;

    console.log("[setup2fa] Generated secret:", secretBase32);
    console.log("[setup2fa] OTPAuth URL:", otpauthUrl);

    const codes = generateBackupCodes(BACKUP_CODES_COUNT, BACKUP_CODE_LENGTH);
    if (!twoFactor) {
      twoFactor = await TwoFactorAuth.create({
        userId,
        tempSecret: secretBase32,
        backupCodes: codes.map(code => code.hashed)
      });
    } else {
      twoFactor.tempSecret = secretBase32;
      twoFactor.backupCodes = codes.map(code => code.hashed);
      await twoFactor.save();
    }

    // Verify what was actually saved to DB
    const check = await TwoFactorAuth.findOne({ userId }).select("+tempSecret");
    console.log("[setup2fa] DB stored tempSecret:", check?.tempSecret);
    console.log("[setup2fa] Secrets match:", check?.tempSecret === secretBase32);

    const qr = await generateQrCode({ otpauthUrl });
    return { qr, codes: codes.map(code => code.plain) };
  }

  static async verify2faSetup({
    userId,
    code
  }: {
    userId: string;
    code: string;
  }) {
    const twoFactor = await TwoFactorAuth.findOne({ userId }).select(
      "+tempSecret"
    );

    console.log({ twoFactor });

    const user = await User.findById(userId);

    if (!user) {
      throw ApiError.unauthorized("Unauthorized access");
    }

    if (!twoFactor) {
      throw ApiError.badRequest("2FA setup not initiated");
    }

    if (twoFactor.enabled && !twoFactor.tempSecret) {
      throw ApiError.badRequest("2FA is already enabled");
    }

    if (!twoFactor.tempSecret) {
      throw ApiError.badRequest("2FA setup not initiated");
    }

    console.log("[verify2faSetup] tempSecret from DB:", twoFactor.tempSecret);
    console.log("[verify2faSetup] code from user:", code);
    console.log("[verify2faSetup] code type:", typeof code);
    console.log("[verify2faSetup] code length:", code.length);

    const isValid = verifyTOTP({
      secret: twoFactor.tempSecret,
      token: code
    });
    console.log("[verify2faSetup] isValid:", isValid);

    if (!isValid) {
      // let lockUntil = null;

      // let newAttempts = user.failedLoginAttempts + 1;

      // if (newAttempts >= LOGIN_MAX_ATTEMPTS) {
      //   lockUntil = new Date(Date.now() + LOCK_TIME_MS);
      // }

      // await User.updateOne(
      //   {
      //     _id: user._id
      //   },
      //   {
      //     failedLoginAttempts: newAttempts,
      //     lockUntil
      //   }
      // );
      throw ApiError.badRequest("Invalid 2FA code");
    }

    twoFactor.secret = twoFactor.tempSecret;
    twoFactor.tempSecret = null;
    twoFactor.enabled = true;
    twoFactor.enabledAt = new Date();

    await User.updateOne(
      {
        _id: user._id
      },
      {
        failedLoginAttempts: 0,
        lockUntil: null
      }
    );

    const updatedTwoFactor = await twoFactor.save();
    if (!updatedTwoFactor) {
      throw ApiError.server("Failed to update 2FA");
    }

    return { message: "2FA setup verified successfully!" };
  }

  static async verifyOtpDuringLogin({
    userId,
    code
  }: {
    userId: string;
    code: string;
  }) {
    const twoFactor = await TwoFactorAuth.findOne({ userId }).select("+secret");

    if (!twoFactor || !twoFactor.secret || !twoFactor.enabled) {
      throw ApiError.badRequest("2FA setup not initiated");
    }

    const isValid = await verifyTOTP({
      secret: twoFactor.secret,
      token: code
    });

    if (!isValid) {
      throw ApiError.badRequest("Invalid 2FA code");
    }

    twoFactor.lastUsedAt = new Date();
    await twoFactor.save();

    return { message: "2FA code verified successfully!" };
  }

  static async disable2fa({ userId }: { userId: string }) {
    const twoFactor = await TwoFactorAuth.findOne({ userId });

    if (!twoFactor || !twoFactor.enabled) {
      throw ApiError.badRequest("2FA setup not initiated");
    }

    twoFactor.enabled = false;
    twoFactor.enabledAt = null;
    twoFactor.tempSecret = null;
    twoFactor.secret = null;
    twoFactor.backupCodes = [];
    await twoFactor.save();
  }

  static async get2faStatus({ userId }: { userId: string }) {
    const twoFactor = await TwoFactorAuth.findOne({ userId }).select(
      "+backupCodes"
    );

    if (!twoFactor) {
      throw ApiError.badRequest("2FA setup not initiated");
    }

    return {
      enabled: twoFactor.enabled,
      enabledAt: twoFactor.enabledAt,
      lastUsedAt: twoFactor.lastUsedAt,
      remainingBackupCodes: twoFactor?.backupCodes?.length
    };
  }

  static async regenerateBackupCodes({ userId }: { userId: string }) {
    const twoFactor = await TwoFactorAuth.findOne({ userId }).select(
      "+backupCodes"
    );

    if (!twoFactor || !twoFactor.enabled || !twoFactor.enabledAt) {
      throw ApiError.badRequest("2FA setup not initiated");
    }

    const codes = generateBackupCodes(BACKUP_CODES_COUNT, BACKUP_CODE_LENGTH);

    twoFactor.backupCodes = codes.map(code => code.hashed);
    await twoFactor.save();

    return { codes: codes.map(code => code.plain) };
  }

  static async verifyBackupCode({
    userId,
    code
  }: {
    userId: string;
    code: string;
  }) {
    const twoFactor = await TwoFactorAuth.findOne({ userId }).select(
      "+backupCodes"
    );

    if (!twoFactor || !twoFactor.backupCodes) {
      throw ApiError.badRequest("2FA setup not initiated");
    }

    const hashedCode = generateHashedToken(code);

    const isValid = twoFactor.backupCodes.includes(hashedCode);
    console.log({ isValid });
    if (!isValid) {
      throw ApiError.badRequest("Invalid backup code");
    }

    const index = twoFactor.backupCodes.indexOf(hashedCode);

    if (index === -1) {
      throw ApiError.badRequest("Invalid backup code");
    }

    twoFactor.backupCodes.splice(index, 1);
    twoFactor.lastUsedAt = new Date();
    await twoFactor.save();

    return { message: "Backup code verified successfully!" };
  }
}
