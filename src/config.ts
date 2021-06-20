import { config as dconfig } from "https://deno.land/x/dotenv/mod.ts";
export { config };
export class Config {
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksEndpoint: string;
  discoveryEndpoint: string;
  clientId: string;
  clientSecret: string;
  issuer: string;

  constructor() {
    const c = dconfig();
    this.authorizationEndpoint = c.AUTHORIZATION_ENDPOINT;
    this.discoveryEndpoint = c.DISCOVERY_ENDPOINT;
    this.tokenEndpoint = c.TOKEN_ENDPOINT;
    this.jwksEndpoint = c.JWKS_ENDPOINT;
    this.clientId = c.CLIENT_ID;
    this.clientSecret = c.CLIENT_SECRET;
    this.issuer = c.ISSUER;
  }
}

const config = new Config();
