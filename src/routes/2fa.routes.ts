import { Router } from "express";
import {
  disable2fa,
  get2faStatus,
  regenerateBackupCodes,
  setup2fa,
  verify2faSetup,
  verifyBackupCode
} from "../controllers/2fa.controller";
import { verifyAuthentication } from "../middlewares/verify-auth";
import { validateRequest } from "../middlewares/validate-request";
import { Verify2faSchema, VerifyBackupCodeSchema } from "../validators/2fa";
import { checkUserAccountRestriction } from "../middlewares/user-account-restriction";

const router = Router();

router.use(verifyAuthentication);
router.use(checkUserAccountRestriction);

router.post("/setup", setup2fa);
router.post("/recovery", setup2fa);

router.post("/setup/verify", validateRequest(Verify2faSchema), verify2faSetup);

router.post("/disable", disable2fa);

router.post("/codes/regenerate", regenerateBackupCodes);

router.post(
  "/codes/verify",
  validateRequest(VerifyBackupCodeSchema),
  verifyBackupCode
);

router.get("/status", get2faStatus);

export default router;
