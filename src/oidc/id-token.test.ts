import {
  assertThrows,
  assertThrowsAsync,
} from "https://deno.land/std@0.99.0/testing/asserts.ts";
import { IdToken, JWKs, JWKsProvider } from "./id-token.ts";
import { discovery } from "./discovery.ts";
import { config } from "../config.ts";
import { create } from "https://deno.land/x/djwt@v2.2/mod.ts";
import { RSA } from "https://deno.land/x/god_crypto@v1.4.8/mod.ts";

Deno.test("invalid jwt", () => {
  assertThrows(() => {
    new IdToken("aaa");
  }, Error);
});

Deno.test("issuer claim unmatched", async () => {
  await assertThrowsAsync(async () => {
    discovery.issuer = "aaa";
    const jwt = await create(
      { alg: "HS256", typ: "JWT" },
      { iss: "bbb" },
      "secret",
    );
    const token = new IdToken(jwt);
    await token.validate("nonce", new NullJWKsProvider());
  }, Error);
});

Deno.test("single string audience claim unmatched", async () => {
  await assertThrowsAsync(async () => {
    discovery.issuer = "aaa";
    config.clientId = "xxx";

    const jwt = await create(
      { alg: "HS256", typ: "JWT" },
      { iss: "aaa", aud: "yyy" },
      "secret",
    );
    const token = new IdToken(jwt);
    await token.validate("nonce", new NullJWKsProvider());
  }, Error);
});

Deno.test("array audience claim unmatched", async () => {
  await assertThrowsAsync(async () => {
    discovery.issuer = "aaa";
    config.clientId = "xxx";

    const jwt = await create(
      { alg: "HS256", typ: "JWT" },
      { iss: "aaa", aud: ["yyy", "zzz"] },
      "secret",
    );
    const token = new IdToken(jwt);
    await token.validate("nonce", new NullJWKsProvider());
  }, Error);
});

Deno.test("no azp claim", async () => {
  await assertThrowsAsync(async () => {
    discovery.issuer = "aaa";
    config.clientId = "xxx";

    const jwt = await create(
      { alg: "HS256", typ: "JWT" },
      { iss: "aaa", aud: ["xxx", "yyy"] },
      "secret",
    );
    const token = new IdToken(jwt);
    await token.validate("nonce", new NullJWKsProvider());
  }, Error);
});

Deno.test("azp claim unmatched", async () => {
  await assertThrowsAsync(async () => {
    discovery.issuer = "aaa";
    config.clientId = "xxx";

    const jwt = await create(
      { alg: "HS256", typ: "JWT" },
      { iss: "aaa", aud: ["xxx", "yyy"], azp: "yyy" },
      "secret",
    );
    const token = new IdToken(jwt);
    await token.validate("nonce", new NullJWKsProvider());
  }, Error);
});

Deno.test("alg header unmatched", async () => {
  await assertThrowsAsync(async () => {
    discovery.issuer = "aaa";
    config.clientId = "xxx";
    config.idTokenSignedResponseAlg = "RS256";

    const jwt = await create(
      { alg: "none", typ: "JWT" },
      { iss: "aaa", aud: ["xxx", "yyy"], azp: "xxx" },
      "secret",
    );
    const token = new IdToken(jwt);
    await token.validate("nonce", new NullJWKsProvider());
  }, Error);
});

// TODO
Deno.test("RS256 signature validation failed", async () => {
  await assertThrowsAsync(async () => {
    discovery.issuer = "aaa";
    discovery.jwksUri =
      "http://localhost:18080/auth/realms/master/protocol/openid-connect/certs";
    config.clientId = "xxx";
    config.idTokenSignedResponseAlg = "RS256";

    const jwk = {
      "kid": "oUvujevPUVpoQXj2OkyASmYbxSEOTrOzZy7VP_-YinU",
      "p":
        "9cxIcxn4FxZqOp3m_jwBQ7oZYWXoofqFXyxjaOG8ZL02wFCkklbGCazyw-CzfWQ_CKZSoW1U5hm3jMhr73N4yCpy8mJ1uyg7yPXQmL4L4YrE7Ou6ZSudMg26souwDaWfQqUItfmX9o-fBuEUUMtFhTCHq25RxwZMa7fy6pvSlLs",
      "kty": "RSA",
      "q":
        "pQBhsWecEpu8wbMvXaD7d0dzHm5ZRog80jjXp9-giXOexHJXDRZ5GSl7C7XeAfER7Snm_ssMpgRqxayOYDb4jBUq4tUKaXTKDFqKbzH5LdWgadXURlI_wX4imQxbH0j0kvgZPDn87-cATO5b8fipI8yTUrvbJDKrmkA35w28ZE0",
      "d":
        "deHRqYglj72Y-PpKjMqQKPzlqMrH0iBhUWWxcwez66mdaQ11kWML3HTg6QABsQx-Cp3AiDC19SWnaTI-wsnskdI7ocXxr3S3HW0i1EdYDW3D8sVxkX9y5gMllMzXEG7iP5GHY2eLSynBDoHG7MiYy2lmbcLyeLdFuOnf59cXo0QMPc1D46fQjDwj0RQkp7ZoWmuC2N4A16iUYUPNU0lwdALFsequpvc_G-5m9H3OrDpcqfu3IMZVZqPGEFdX3CdTVWSg46J7RbVIs73xY1g1jQ4axBN1OOpWRBeDdfxFQh3Wdbim4BtfOFyYsjyIwljn04S4eNWuDwywFWm9gDu-WQ",
      "e": "AQAB",
      "use": "sig",
      "qi":
        "KpmRSXOtn-rUR-020d_8riNLxi-g-fsNY8Ki883-NLwFutsZzrARbK354nR9PmvauofYkhGvB71_YdjT-Im0qEL1tLAay3sSba6Pm1QFgQy6A6SDvbt87C4htRXUa4xu_ZWnm7vcn9hqBfHdak-ypYyWuFVibHcmSfipW2PfmZ4",
      "dp":
        "uyDpT2fH7pvMCBBK2ecI92zpAbO6Jgc6HrkGfcTNzswWsNc0U4zofFlFAUdCnwYAzy8A3ZEE_6E4kl_LfKMmow1eMZYwF2qMCXTLeF3HYdBqGA1m_Lr1lDPLnT6nq9wZoX1PYmtA_B9fbLdS5ie7J6lIwITekW0EJUYIFADJkx0",
      "alg": "RS256",
      "dq":
        "oX8zH2GKuAfogyovlROorUGookNdbBSSeywZn_zYc1BQOHS1UWEKnB8miPqz1fCvHBMkPYRd1-yA2QOgwvlq4ikhtazRKRCfZeIElvsxqbPq80vQHhgIwQkFMgmO8psEjwj4IiObtu_BMosmQTqhyiFEnPizb8WMgkiSrrqaBw0",
      "n":
        "nm0Ifuzpps3CWdbEQlyT3skg7fWObvfwWCWvweRZiPTEHtyzAfC64rHrGw5sqcPCs0EInUlat_-wHXLmNAx9p5mOHR94Cn2uFb7U_IU3n9CM3KPq2Un_Ap6snogaJmgCjcAVx8_9fo8o2VngZmMRyonVnBsnCj2iJb40eWNWMjkR8JtDb9FNMx0snA1oIYWfA5BhV08xkZCZfCmHh41s7OIwk4yEPKOxn824wb2IT3Uythl45G5IsNug5z_Zbh6nlzpfydOTUxg68Twp5NirF_LabIY9kMqD9jClq5o9n2cKw60eLpMjWPyuuSDu3VQRnz0waYd8S7AVJDde2MPIPw",
    };

    try {
      RSA.importKey(jwk).pem();
      const jwt = await create(
        {
          alg: "RS256",
          typ: "JWT",
          kid: "oUvujevPUVpoQXj2OkyASmYbxSEOTrOzZy7VP_-YinU",
        },
        { iss: "aaa", aud: ["xxx", "yyy"], azp: "xxx" },
        RSA.importKey(jwk).pem(),
      );
      const token = new IdToken(jwt);
      await token.validate("nonce", new NullJWKsProvider());
    } catch (err) {
      console.error(err);
    }
  }, Error);
});

class ValueBasedJWKsProvider implements JWKsProvider {
  value: JWKs;
  constructor(jwks: any) {
    this.value = new JWKs(jwks);
  }
  findJwk(kid: string): Promise<string> {
    return this.value.findJWKByKeyId(kid);
  }
}

class NullJWKsProvider implements JWKsProvider {
  findJwk(kid: string): Promise<string> {
    throw new Error("Method not implemented.");
  }
}
