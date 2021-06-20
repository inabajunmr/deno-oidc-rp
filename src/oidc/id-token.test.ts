import {
  assertThrows,
  assertThrowsAsync,
} from "https://deno.land/std@0.99.0/testing/asserts.ts";
import { IdToken } from "./id-token.ts";
import { discovery } from "./discovery.ts";
import { config } from "../config.ts";
import { create } from "https://deno.land/x/djwt@v2.2/mod.ts";

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
    await token.validate("nonce");
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
    await token.validate("nonce");
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
      await token.validate("nonce");
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
      await token.validate("nonce");
    }, Error);
  });
  
  Deno.test("azp claim unmatched", async () => {
    await assertThrowsAsync(async () => {
      discovery.issuer = "aaa";
      config.clientId = "xxx";
  
      const jwt = await create(
        { alg: "HS256", typ: "JWT" },
        { iss: "aaa", aud: ["xxx", "yyy"] , azp:"yyy"},
        "secret",
      );
      const token = new IdToken(jwt);
      await token.validate("nonce");
    }, Error);
  });
  
  Deno.test("alg header unmatched", async () => {
    await assertThrowsAsync(async () => {
      discovery.issuer = "aaa";
      config.clientId = "xxx";
      config.idTokenSignedResponseAlg = "RS256"
  
      const jwt = await create(
        { alg: "none", typ: "JWT" },
        { iss: "aaa", aud: ["xxx", "yyy"] , azp:"xxx"},
        "secret",
      );
      const token = new IdToken(jwt);
      await token.validate("nonce");
    }, Error);
  });
  