import { config } from "../config.ts";
export { discovery };

class Discovery {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;

  constructor(
    issuer: string,
    authorizationEndpoint: string,
    tokenEndpoint: string,
    jwksUri: string,
  ) {
    this.issuer = issuer;
    this.authorizationEndpoint = authorizationEndpoint;
    this.tokenEndpoint = tokenEndpoint;
    this.jwksUri = jwksUri;
  }
}

const discover = async () => {
  const res = await fetch(config.discoveryEndpoint);
  const json = await res.json();
  return new Discovery(
    json.issuer,
    json.authorization_endpoint,
    json.token_endpoint,
    json.jwks_uri,
  );
};

const discovery = await discover();
console.log(discovery);
