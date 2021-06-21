import { discovery } from "./discovery.ts";

export interface JWKsProvider {
  findJwk(kid: string): Promise<string>;
}

export class UrlBasedJWKsProvider implements JWKsProvider {
  jwksUrl: string;
  constructor(jwksUrl: string) {
    this.jwksUrl = jwksUrl;
  }
  async findJwk(kid: string): Promise<string> {
    const jwks = await fetch(discovery.jwksUri).then((response) => {
      return response.json();
    });
    const jwk = new JWKs(jwks).findJWKByKeyId(kid);
    return jwk;
  }
}

export class JWKs {
  jwks: any;
  constructor(jwks: any) {
    this.jwks = jwks;
  }
  findJWKByKeyId(kid: string) {
    return this.jwks.keys.find(
      function (x: string) {
        return Object(x).kid == kid;
      },
    );
  }
}
