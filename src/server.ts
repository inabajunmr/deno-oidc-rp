import { Application, Router } from "https://deno.land/x/oak/mod.ts";
import { getQuery } from "https://deno.land/x/oak/helpers.ts";
import {
  adapterFactory,
  engineFactory,
  viewEngine,
} from "https://deno.land/x/view_engine/mod.ts";
import {
  AuthorizationRequestBuilder,
  ResponseType,
  TokenRequest,
  TokenResponse,
} from "./oidc.ts";
import { config } from "https://deno.land/x/dotenv/mod.ts";

const app = new Application();

const ejsEngine = await engineFactory.getEjsEngine();
const oakAdapter = await adapterFactory.getOakAdapter();

app.use(viewEngine(oakAdapter, ejsEngine));

const router = new Router();

router.get("/", (ctx: any) => {
  console.log("Handler: /");
  ctx.render("./template/index.ejs");
});

router.get("/login", (ctx: any) => {
  console.log("Handler: /login");
  const c = config();
  const authEndpoint = c.AUTHORIZATION_ENDPOINT;
  const clientId = c.CLIENT_ID;
  const requestBuilder = new AuthorizationRequestBuilder(
    authEndpoint,
    ["openid"],
    ResponseType.CODE,
    clientId,
    "http://127.0.0.1:8000/callback",
  );
  ctx.response.redirect(requestBuilder.build());
});

router.get("/callback", async (ctx: any) => {
  console.log("Handler: /callback");
  const query = getQuery(ctx, { mergeParams: true });
  console.log(query);
  // TODO check state
  const tokenRequest = new TokenRequest(
    query.code,
    "http://127.0.0.1:8000/callback",
  );
  const response = await tokenRequest.execute();
  const jsonData = await response.json()
  
  try {
    console.log(jsonData);
    const tokenResponse = new TokenResponse(jsonData)
    await tokenResponse.idToken.validate();
    const payload = tokenResponse.idToken.getPayload()
    ctx.render("./template/authenticated.ejs", {"sub": payload.sub});  
  } catch(err) {
    console.error("Error:", err);
    ctx.render("./template/index.ejs");
  }
});

app.use(router.routes());
app.use(router.allowedMethods());

console.log("http://127.0.0.1:8000");
await app.listen("127.0.0.1:8000");
