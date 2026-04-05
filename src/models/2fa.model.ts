import { Document, model, Schema, Types } from "mongoose";

export interface TwoFactorAuth extends Document {
  _id: Types.ObjectId;
  userId: Types.ObjectId;

  enabled: boolean;
  secret: string | null;
  tempSecret: string | null;

  backupCodes: string[];

  enabledAt: Date | null;
  lastUsedAt: Date | null;

  createdAt: Date;
  updatedAt: Date;
}

const twoFactorAuthSchema = new Schema<TwoFactorAuth>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: "User",
      required: [true, "User ID is required"]
    },
    enabled: {
      type: Boolean,
      default: false
    },
    secret: {
      type: String,
      select: false
    },
    tempSecret: {
      type: String,
      select: false
    },
    backupCodes: {
      type: [String],
      select: false
    },
    enabledAt: {
      type: Date
    },
    lastUsedAt: {
      type: Date
    }
  },
  {
    timestamps: true
  }
);

const TwoFactorAuth = model("2fa", twoFactorAuthSchema);

export default TwoFactorAuth;
