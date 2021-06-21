import { getQuery } from "https://deno.land/x/oak/helpers.ts";
import { TokenRequest, TokenResponse } from "../oidc/token-request.ts";
import { UrlBasedJWKsProvider } from "../oidc/jwks-provider.ts";
import { discovery } from "../oidc/discovery.ts";

export { callback };

const callback = async (ctx: any) => {
  console.log("Handler: /callback");

  const query = getQuery(ctx, { mergeParams: true });
  console.log(query);
  const state = ctx.cookies.get("state");
  ctx.cookies.delete("state");
  if (query.state !== state) {
    console.log("state unmatched.");
    ctx.render("./template/index.ejs");
  }

  const tokenRequest = new TokenRequest(
    query.code,
    "http://127.0.0.1:8000/callback",
  );
  const response = await tokenRequest.execute();
  const jsonData = await response.json();

  try {
    const tokenResponse = new TokenResponse(jsonData);
    const nonce = ctx.cookies.get("nonce");
    ctx.cookies.delete("nonce");

    await tokenResponse.idToken.validate(
      nonce,
      new UrlBasedJWKsProvider(discovery.jwksUri),
    );

    const payload = tokenResponse.idToken.payload;
    ctx.render("./template/authenticated.ejs", { "sub": payload.sub });
  } catch (err) {
    console.error("Error:", err);
    ctx.render("./template/index.ejs");
  }
};
