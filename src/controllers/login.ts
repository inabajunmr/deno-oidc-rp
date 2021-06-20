import { Context } from "https://deno.land/x/oak/mod.ts";
import {
  AuthorizationRequestBuilder,
  ResponseType,
} from "../oidc/authorization-request.ts";
import { config } from "https://deno.land/x/dotenv/mod.ts";
export { login };

const login = (ctx: Context) => {
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
  ctx.cookies.set("state", requestBuilder.state);
  ctx.cookies.set("nonce", requestBuilder.nonce);
  ctx.response.redirect(requestBuilder.build());
};
