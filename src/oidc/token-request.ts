import { config } from "../config.ts";
import { IdToken } from "./id-token.ts";
import * as base64 from "https://denopkg.com/chiefbiiko/base64/mod.ts";

export class TokenRequest {
  code: string;
  redirectUti: string;

  constructor(code: string, redirectUri: string) {
    this.code = code;
    this.redirectUti = redirectUri;
  }

  execute() {
    const params = new URLSearchParams([["grant_type", "authorization_code"], [
      "code",
      this.code,
    ], ["redirect_uri", this.redirectUti]]);
    const credentials = "Basic " +
      base64.fromUint8Array(
        new TextEncoder().encode(config.clientId + ":" + config.clientSecret),
      );

    const response = fetch(config.tokenEndpoint, {
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
