import { config as dconfig } from "https://deno.land/x/dotenv/mod.ts";
export { config };
export class Config {
  discoveryEndpoint: string;
  clientId: string;
  clientSecret: string;
  issuer: string;
  idTokenSignedResponseAlg: string;

  constructor() {
    const c = dconfig();
    this.discoveryEndpoint = c.DISCOVERY_ENDPOINT;
    this.clientId = c.CLIENT_ID;
    this.clientSecret = c.CLIENT_SECRET;
    this.issuer = c.ISSUER;
    if (c.ID_TOKEN_SIGNED_RESPONSE_ALG) {
      this.idTokenSignedResponseAlg = c.ID_TOKEN_SIGNED_RESPONSE_ALG;
    } else {
      this.idTokenSignedResponseAlg = "RS256";
    }
  }
}

const config = new Config();
