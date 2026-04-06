import { Request } from "express";
import { OTP_TYPES } from "../constants/auth";

export type OTPType = (typeof OTP_TYPES)[number];

export type Role = "user" | "admin";

export interface UserRequest extends Request {
  user?: {
    _id?: string;
    role?: Role;
  };
}

export interface IUser {
  _id: string;
  name: string;
  email: string;
  role: Role;
  isEmailVerified: boolean;
  createdAt: string;
  updatedAt: string;
  avatar: {
    public_id: string;
    url: string;
    size: number;
  };
  twoFactor: {
    enabled: boolean;
    enabledAt: string;
    backupCodesRemaining: number;
  };
}
