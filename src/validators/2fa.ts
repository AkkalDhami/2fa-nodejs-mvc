import z from "zod";
import { BACKUP_CODE_LENGTH } from "../constants/auth";

export const Verify2faSchema = z.object({
  code: z.string().min(6, "Please enter a valid code")
});

export const VerifyBackupCodeSchema = z.object({
  code: z.string().min(BACKUP_CODE_LENGTH, "Please enter a valid backup code")
});
