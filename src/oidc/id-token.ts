import {
  decode,
  Header,
  Payload,
  validate,
  verify,
} from "https://deno.land/x/djwt@v2.2/mod.ts";
import { RSA } from "https://deno.land/x/god_crypto@v1.4.8/mod.ts";
import { config } from "../config.ts";
import { discovery } from "./discovery.ts";
import { JWKsProvider } from "./jwks-provider.ts";

export class IdToken {
  value: string;
  header: Header;
  payload: Payload;
  signature: string;

  constructor(idToken: string) {
    this.value = idToken;
    const token = validate(decode(idToken));
    this.header = token.header;
    this.payload = token.payload;
    this.signature = token.signature;
  }

  async validate(nonce: string, jwksProvider: JWKsProvider) {
    // 1. If the ID Token is encrypted, decrypt it using the keys and algorithms that the Client specified during Registration that the OP was to use to encrypt the ID Token. If encryption was negotiated with the OP at Registration time and the ID Token is not encrypted, the RP SHOULD reject it.
    // TODO encrypted ID Token unsupported

    // 2. The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery) MUST exactly match the value of the iss (issuer) Claim.
    this.validateIssuer(this.payload.iss, discovery.issuer);

    // 3. The Client MUST validate that the aud (audience) Claim contains its client_id value registered at the Issuer identified by the iss (issuer) Claim as an audience. The aud (audience) Claim MAY contain an array with more than one element. The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience, or if it contains additional audiences not trusted by the Client.
    this.validateAudienceAndAuthorizedParty(
      this.payload.aud,
      this.payload.azp,
      config.clientId,
    );

    // 6. If the ID Token is received via direct communication between the Client and the Token Endpoint (which it is in this flow), the TLS server validation MAY be used to validate the issuer in place of checking the token signature. The Client MUST validate the signature of all other ID Tokens according to JWS [JWS] using the algorithm specified in the JWT alg Header Parameter. The Client MUST use the keys provided by the Issuer.
    // 7. The alg value SHOULD be the default of RS256 or the algorithm sent by the Client in the id_token_signed_response_alg parameter during Registration.
    // 8. If the JWT alg Header Parameter uses a MAC based algorithm such as HS256, HS384, or HS512, the octets of the UTF-8 representation of the client_secret corresponding to the client_id contained in the aud (audience) Claim are used as the key to validate the signature. For MAC based algorithms, the behavior is unspecified if the aud is multi-valued or if an azp value is present that is different than the aud value.
    await this.validateSignature(
      this.header,
      config.idTokenSignedResponseAlg,
      jwksProvider,
      config.clientSecret,
      this.value,
    );

    // 9. The current time MUST be before the time represented by the exp Claim.
    this.validateExp(this.payload.exp);

    // 10. The iat Claim can be used to reject tokens that were issued too far away from the current time, limiting the amount of time that nonces need to be stored to prevent attacks. The acceptable range is Client specific.
    this.validateIat(this.payload.iat);

    // 11. If a nonce value was sent in the Authentication Request, a nonce Claim MUST be present and its value checked to verify that it is the same value as the one that was sent in the Authentication Request. The Client SHOULD check the nonce value for replay attacks. The precise method for detecting replay attacks is Client specific.
    this.validateNonce(this.payload.nonce, nonce);

    // 12. If the acr Claim was requested, the Client SHOULD check that the asserted Claim Value is appropriate. The meaning and processing of acr Claim Values is out of scope for this specification.
    // If some policy needs acr, need to validate it.

    // 13. If the auth_time Claim was requested, either through a specific request for this Claim or by using the max_age parameter, the Client SHOULD check the auth_time Claim value and request re-authentication if it determines too much time has elapsed since the last End-User authentication.
    this.validateAuthTime(this.payload.auth_time);
  }

  private validateAuthTime(authTime: unknown) {
    if (
      authTime !== undefined &&
      typeof (authTime) === "number" &&
      authTime < Date.now() / 1000 - 3600
    ) {
      console.log("auth_time is too old.");
      throw new Error("auth_time is too old.");
    }
  }

  private validateNonce(payloadNonce: unknown, authzRequestNonce: string) {
    if (payloadNonce !== authzRequestNonce) {
      console.log("nonce unmatched.");
      throw new Error("nonce unmatched.");
    }
  }

  private validateIat(iat: number | undefined) {
    if (
      iat !== undefined &&
      iat < Date.now() / 1000 - 3600
    ) {
      console.log("iat is too old.");
      throw new Error("iat is too old.");
    }
  }

  private validateExp(exp: number | undefined) {
    if (
      exp === undefined || exp < Date.now() / 1000
    ) {
      console.log("expired id token.");
      throw new Error("expired id token.");
    }
  }

  private async validateSignature(
    header: Header,
    idTokenSignedResponseAlg: string,
    jwksProvider: JWKsProvider,
    clientSecret: string,
    jwt: string,
  ) {
  if (header.alg !== idTokenSignedResponseAlg) {
    console.log("alg must be " + idTokenSignedResponseAlg);
    throw new Error("alg must be " + idTokenSignedResponseAlg);
  }

  try {
    if (["RS256", "RS512", "PS256", "PS512"].includes(header.alg)) {
      const jwk = await jwksProvider.findJwk(Object(header).kid);
      await verify(jwt, RSA.importKey(jwk).pem(), header.alg);
    } else if (["HS256", "HS512"].includes(header.alg)) {
      await verify(jwt, clientSecret, header.alg);
    } else {
      throw new Error(`${header.alg} is not supported.`);
    }
  } catch (err) {
    console.log(err.message);
    throw err;
  }
}

  private validateIssuer(
    payloadIssuer: string | undefined,
    discoveryIssuer: string,
  ) {
    if (payloadIssuer !== discoveryIssuer) {
      console.log("unexpected issuer.");
      throw new Error("unexpected issuer.");
    }
  }

  private validateAudienceAndAuthorizedParty(
    payloadAud: string | string[] | undefined,
    payloadAzp: unknown,
    clientId: string,
  ) {
    if (payloadAud === undefined) {
      console.log("ID Token must have aud claim.");
      throw Error("ID Token must have aud claim.");
    }
    if (typeof payloadAud === "string") {
      if (payloadAud !== clientId) {
        console.log("aud must be client_id.");
        throw new Error("aud must be client_id.");
      }
    } else {
      if (!payloadAud?.includes(clientId)) {
        console.log("aud must include client_id.");
        throw new Error("aud must include client_id.");
      }
      // 4. If the ID Token contains multiple audiences, the Client SHOULD verify that an azp Claim is present.
      if (payloadAzp === undefined) {
        console.log("aud is array so azp is required.");
        throw new Error("aud is array so azp is required.");
      }
      // 5. If an azp (authorized party) Claim is present, the Client SHOULD verify that its client_id is the Claim Value.
      if (payloadAzp !== clientId) {
        console.log("azp must be client_id.");
        throw new Error("azp must be client_id.");
      }
    }
  }
}
