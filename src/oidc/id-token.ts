import { decode, validate, verify } from "https://deno.land/x/djwt@v2.2/mod.ts";
import { RSA } from "https://deno.land/x/god_crypto@v1.4.8/mod.ts";
import { config } from "../config.ts";

export class IdToken {
  value: string;

  constructor(idToken: string) {
    this.value = idToken;
  }

  async validate(nonce: string) {
    const jwks = await fetch(config.jwksEndpoint).then((response) => {
      return response.json();
    });

    // signature
    const { header, payload } = validate(decode(this.value));
    console.log(payload);

    if (header.alg === "none") {
      throw new Error("alg:none isn't allowed.");
    }

    const jwk = this.findJWKByKeyId(Object(header).kid, jwks);
    await verify(this.value, RSA.importKey(jwk).pem(), header.alg);

    if (payload.iss !== config.issuer) {
      throw new Error("unexpected issuer.");
    }

    if (payload.aud !== config.clientId) {
      // TODO aud can be array
      throw new Error("aud must be client_id.");
    }

    // TODO azp

    // TODO If the JWT alg Header Parameter uses a MAC based algorithm such as HS256, HS384, or HS512, the octets of the UTF-8 representation of the client_secret corresponding to the client_id contained in the aud (audience) Claim are used as the key to validate the signature. For MAC based algorithms, the behavior is unspecified if the aud is multi-valued or if an azp value is present that is different than the aud value.

    if (payload.exp === undefined || payload.exp > Date.now() * 1000) {
      throw new Error("expired id token.");
    }

    if (payload.nonce !== nonce) {
      throw new Error("nonce unmatched.");
    }
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
