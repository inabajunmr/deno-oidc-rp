import { Application, Router, send } from "https://deno.land/x/oak/mod.ts";
import {viewEngine, engineFactory, adapterFactory} from 'https://deno.land/x/view_engine/mod.ts'
import { AuthorizationRequestBuilder, ResponseType } from "./oauth2.ts";

const app = new Application();

const ejsEngine = await engineFactory.getEjsEngine();
const oakAdapter = await adapterFactory.getOakAdapter();

app.use(viewEngine(oakAdapter, ejsEngine));

const router = new Router();

router.get('/', (ctx: any) => {
  ctx.render('index.ejs');
});

router.get('/login', (ctx: any) => {
  const requestBuilder =new AuthorizationRequestBuilder("http://example.com", ["openid"], ResponseType.CODE, "clientId", "http://example.com/callback");
  ctx.response.redirect(requestBuilder.build())
});

app.use(router.routes());
app.use(router.allowedMethods());

console.log("http://127.0.0.1:8000");
await app.listen("127.0.0.1:8000");
