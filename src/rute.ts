import { Router } from "https://deno.land/x/oak/mod.ts";
import { root } from "./controllers/root.ts";
import { login } from "./controllers/login.ts";
import { callback } from "./controllers/callback.ts";
export { router };
const router = new Router();

router.get("/", root);
router.get("/login", login);
router.get("/callback", callback);
