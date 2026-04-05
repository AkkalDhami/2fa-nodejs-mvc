import { Router } from "express";
import healthRoutes from "./health.routes";
import authRoutes from "./auth.routes";
import oauthRoutes from "./oauth.routes";
import TwoFaRoutes from "./2fa.routes";

const router = Router();

router.use("/v1/health", healthRoutes);

router.use("/v1/auth", authRoutes);
router.use("/v1/auth/2fa", TwoFaRoutes);


router.use("/auth", oauthRoutes); //* Here versioning is not given because, in google and github callback routes, we are not using versioning. process.env.GOOGLE_REDIRECT_URI



export default router;
