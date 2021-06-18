import { v4 } from "https://deno.land/std/uuid/mod.ts";
import { config } from "https://deno.land/x/dotenv/mod.ts";
import * as base64 from "https://denopkg.com/chiefbiiko/base64/mod.ts";
import { decode, validate, verify } from "https://deno.land/x/djwt@v2.2/mod.ts";
import { RSA } from "https://deno.land/x/god_crypto@v1.4.8/mod.ts";

export class AuthorizationRequestBuilder {
  uri: string;
  scope: string[];
  responseType: ResponseType;
  clientId: string;
  redirectUri: string;
  state: string;
  nonce: string;

  constructor(
    uri: string,
    scope: string[],
    responseType: ResponseType,
    clientId: string,
    redirectUri: string,
  ) {
    this.uri = uri;
    this.scope = scope;
    this.responseType = responseType;
    this.clientId = clientId;
    this.redirectUri = redirectUri;
    this.state = v4.generate();
    this.nonce = v4.generate();
  }

  build(): string {
    const url = new URL(this.uri);
    url.searchParams.append("scope", this.scope.join(" "));
    url.searchParams.append("response_type", this.responseType.toString());
    url.searchParams.append("client_id", this.clientId);
    url.searchParams.append("redirect_uri", this.redirectUri);
    url.searchParams.append("state", this.state);
    url.searchParams.append("nonce", this.nonce);
    return url.href;
  }
}

export enum ResponseType {
  CODE = "code",
  IMPLICIT = "implicit",
}

export class TokenRequest {
  code: string;
  redirectUti: string;

  constructor(code: string, redirectUri: string) {
    this.code = code;
    this.redirectUti = redirectUri;
  }

  execute() {
    const c = config();
    const params = new URLSearchParams([["grant_type", "authorization_code"], [
      "code",
      this.code,
    ], ["redirect_uri", this.redirectUti]]);
    const credentials = "Basic " +
      base64.fromUint8Array(
        new TextEncoder().encode(c.CLIENT_ID + ":" + c.CLIENT_SECRET),
      );

    const response = fetch(c.TOKEN_ENDPOINT, {
      method: "POST",
      headers: {
        "Authorization": credentials,
      },
      body: params,
    });
    return response;
  }
}

export class TokenResponse {
  accessToken: string;
  idToken: IdToken;

  constructor(tokenResponse: any) {
    this.accessToken = tokenResponse.access_token;
    this.idToken = new IdToken(tokenResponse.id_token);
  }
}

export class IdToken {
  value: string;

  constructor(idToken: string) {
    this.value = idToken;
  }

  async validate() {
    const c = config();
    const jwks = await fetch(c.JWKS_ENDPOINT).then((response) => {
      return response.json();
    });

    // signature
    const { header, payload } = validate(decode(this.value));

    if (header.alg === "none") {
      throw new Error("alg:none isn't allowed.");
    }

    const jwk = this.findJWKByKeyId(Object(header).kid, jwks);
    await verify(this.value, RSA.importKey(jwk).pem(), header.alg);

    if (payload.iss !== c.ISSUER) {
      throw new Error("unexpected issuer.");
    }

    if (payload.aud !== c.CLIENT_ID) {
      // TODO aud can be array
      throw new Error("aud must be client_id.");
    }

    // TODO azp

    // TODO If the JWT alg Header Parameter uses a MAC based algorithm such as HS256, HS384, or HS512, the octets of the UTF-8 representation of the client_secret corresponding to the client_id contained in the aud (audience) Claim are used as the key to validate the signature. For MAC based algorithms, the behavior is unspecified if the aud is multi-valued or if an azp value is present that is different than the aud value.

    if (payload.exp === undefined || payload.exp > Date.now() * 1000) {
      throw new Error("expired id token");
    }

    // TODO nonce

  }

  getPayload() {
    const { payload } = validate(decode(this.value));
    return payload;
  }

  findJWKByKeyId(kid: string, jwks: any) {
    return jwks.keys.find(
      function (x: string) {
        return Object(x).kid == kid;
      },
    );
  }
}
