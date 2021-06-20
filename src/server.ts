import { Application } from "https://deno.land/x/oak/mod.ts";
import {
  adapterFactory,
  engineFactory,
  viewEngine,
} from "https://deno.land/x/view_engine/mod.ts";
import { router } from "./rute.ts";

const app = new Application();

const ejsEngine = await engineFactory.getEjsEngine();
const oakAdapter = await adapterFactory.getOakAdapter();

app.use(viewEngine(oakAdapter, ejsEngine));

app.use(router.routes());
app.use(router.allowedMethods());

console.log("http://127.0.0.1:8000");
await app.listen("127.0.0.1:8000");
