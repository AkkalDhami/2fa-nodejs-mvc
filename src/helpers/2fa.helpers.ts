import * as OTPAuth from "otpauth";
import QRCode from "qrcode"; //npm i --save-dev @types/qrcode

import speakeasy from "speakeasy"; //npm i --save-dev @types/speakeasy

import path from "node:path";
import fs from "node:fs";

import env from "../configs/env";

export const generateTOTP = ({
  email,
  secret
}: {
  email: string;
  secret?: string;
}): OTPAuth.TOTP => {
  const totp = new OTPAuth.TOTP({
    issuer: env.OTP_ISSUER,
    label: email,
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    ...(secret ? { secret: OTPAuth.Secret.fromBase32(secret) } : {})
  });
  return totp;
};

export const generateQrCode = async ({
  otpauthUrl
}: {
  otpauthUrl: string;
}) => {
  const qrCode = await QRCode.toDataURL(otpauthUrl);

  const qrCodePath = path.join(process.cwd(), "public");
  if (!fs.existsSync(qrCodePath)) {
    fs.mkdirSync(qrCodePath, { recursive: true });
  }

  QRCode.toFile(
    `${qrCodePath}/qr-${Date.now()}.png`,
    otpauthUrl,
    function (err) {
      if (err) throw err;
      console.log("done");
    }
  );
  return qrCode;
};

export const verifyTOTP = ({
  token,
  secret
}: {
  token: string;
  secret: string;
}): boolean => {
  const totp = new OTPAuth.TOTP({
    issuer: env.OTP_ISSUER,
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    secret: OTPAuth.Secret.fromBase32(secret)
  });
  return totp.validate({ token, window: 2 }) !== null;
};
