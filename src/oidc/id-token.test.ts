import {
  assertThrows,
  assertThrowsAsync,
} from "https://deno.land/std@0.99.0/testing/asserts.ts";
import { JWKs, JWKsProvider } from "./jwks-provider.ts";
import { IdToken } from "./id-token.ts";
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

Deno.test("RS256 signature validation failed", async () => {
  await assertThrowsAsync(async () => {
    discovery.issuer = "aaa";
    config.clientId = "xxx";
    config.idTokenSignedResponseAlg = "RS256";

    const jwt = await create(
      {
        alg: "RS256",
        typ: "JWT",
        kid: testJwks.keys[1].kid, // unmatched key
      },
      { iss: "aaa", aud: ["xxx", "yyy"], azp: "xxx" },
      RSA.importKey(testJwks.keys[0]).pem(),
    );
    const token = new IdToken(jwt);
    await token.validate("nonce", new ValueBasedJWKsProvider(testJwks));
  }, Error);
});

Deno.test("HS256 signature validation failed", async () => {
  await assertThrowsAsync(async () => {
    discovery.issuer = "aaa";
    config.clientId = "xxx";
    config.clientSecret = "secret";
    config.idTokenSignedResponseAlg = "HS256";

    const jwt = await create(
      {
        alg: "HS256",
        typ: "JWT",
      },
      { iss: "aaa", aud: ["xxx", "yyy"], azp: "xxx" },
      "invalid",
    );
    const token = new IdToken(jwt);
    await token.validate("nonce", new ValueBasedJWKsProvider(testJwks));
  }, Error);
});

Deno.test("expired", async () => {
  await assertThrowsAsync(async () => {
    discovery.issuer = "aaa";
    config.clientId = "xxx";
    config.idTokenSignedResponseAlg = "RS256";

    const jwt = await create(
      {
        alg: "RS256",
        typ: "JWT",
        kid: testJwks.keys[0].kid,
      },
      { iss: "aaa", aud: ["xxx", "yyy"], azp: "xxx", exp: Date.now() / 1000 },
      RSA.importKey(testJwks.keys[0]).pem(),
    );
    const token = new IdToken(jwt);
    await token.validate("nonce", new ValueBasedJWKsProvider(testJwks));
  }, Error);
});

Deno.test("too old iat", async () => {
  await assertThrowsAsync(async () => {
    discovery.issuer = "aaa";
    config.clientId = "xxx";
    config.idTokenSignedResponseAlg = "RS256";

    const jwt = await create(
      {
        alg: "RS256",
        typ: "JWT",
        kid: testJwks.keys[0].kid,
      },
      {
        iss: "aaa",
        aud: ["xxx", "yyy"],
        azp: "xxx",
        exp: Date.now() / 1000 + 5,
        iat: Date.now() / 1000 - 3700,
      },
      RSA.importKey(testJwks.keys[0]).pem(),
    );
    const token = new IdToken(jwt);
    await token.validate("nonce", new ValueBasedJWKsProvider(testJwks));
  }, Error);
});

Deno.test("nonce unmatched", async () => {
  await assertThrowsAsync(async () => {
    discovery.issuer = "aaa";
    config.clientId = "xxx";
    config.idTokenSignedResponseAlg = "RS256";

    const jwt = await create(
      {
        alg: "RS256",
        typ: "JWT",
        kid: testJwks.keys[0].kid,
      },
      {
        iss: "aaa",
        aud: ["xxx", "yyy"],
        azp: "xxx",
        exp: Date.now() / 1000 + 5,
        iat: Date.now() / 1000 - 3500,
        nonce: "nonce",
      },
      RSA.importKey(testJwks.keys[0]).pem(),
    );
    const token = new IdToken(jwt);
    await token.validate("invalid", new ValueBasedJWKsProvider(testJwks));
  }, Error);
});

Deno.test("too old auth_time", async () => {
  await assertThrowsAsync(async () => {
    discovery.issuer = "aaa";
    config.clientId = "xxx";
    config.idTokenSignedResponseAlg = "RS256";

    const jwt = await create(
      {
        alg: "RS256",
        typ: "JWT",
        kid: testJwks.keys[0].kid,
      },
      {
        iss: "aaa",
        aud: ["xxx", "yyy"],
        azp: "xxx",
        exp: Date.now() / 1000 + 5,
        iat: Date.now() / 1000 - 3500,
        auth_time: Date.now() / 1000 - 3700,
        nonce: "nonce",
      },
      RSA.importKey(testJwks.keys[0]).pem(),
    );
    const token = new IdToken(jwt);
    await token.validate("nonce", new ValueBasedJWKsProvider(testJwks));
  }, Error);
});

Deno.test("RS256 valid", async () => {
  discovery.issuer = "aaa";
  config.clientId = "xxx";
  config.idTokenSignedResponseAlg = "RS256";

  const jwt = await create(
    {
      alg: "RS256",
      typ: "JWT",
      kid: testJwks.keys[0].kid,
    },
    {
      iss: "aaa",
      aud: ["xxx", "yyy"],
      azp: "xxx",
      exp: Date.now() / 1000 + 5,
      iat: Date.now() / 1000 - 3500,
      auth_time: Date.now() / 1000 - 3500,
      nonce: "nonce",
    },
    RSA.importKey(testJwks.keys[0]).pem(),
  );
  const token = new IdToken(jwt);
  await token.validate("nonce", new ValueBasedJWKsProvider(testJwks));
});

Deno.test("RS512 valid", async () => {
  discovery.issuer = "aaa";
  config.clientId = "xxx";
  config.idTokenSignedResponseAlg = "RS512";

  const jwt = await create(
    {
      alg: "RS512",
      typ: "JWT",
      kid: testJwks.keys[2].kid,
    },
    {
      iss: "aaa",
      aud: ["xxx", "yyy"],
      azp: "xxx",
      exp: Date.now() / 1000 + 5,
      iat: Date.now() / 1000 - 3500,
      auth_time: Date.now() / 1000 - 3500,
      nonce: "nonce",
    },
    RSA.importKey(testJwks.keys[2]).pem(),
  );
  const token = new IdToken(jwt);
  await token.validate("nonce", new ValueBasedJWKsProvider(testJwks));
});

Deno.test("PS256 valid", async () => {
  discovery.issuer = "aaa";
  config.clientId = "xxx";
  config.idTokenSignedResponseAlg = "PS256";

  const jwt = await create(
    {
      alg: "PS256",
      typ: "JWT",
      kid: testJwks.keys[3].kid,
    },
    {
      iss: "aaa",
      aud: ["xxx", "yyy"],
      azp: "xxx",
      exp: Date.now() / 1000 + 5,
      iat: Date.now() / 1000 - 3500,
      auth_time: Date.now() / 1000 - 3500,
      nonce: "nonce",
    },
    RSA.importKey(testJwks.keys[3]).pem(),
  );
  const token = new IdToken(jwt);
  await token.validate("nonce", new ValueBasedJWKsProvider(testJwks));
});
Deno.test("PS512 valid", async () => {
  discovery.issuer = "aaa";
  config.clientId = "xxx";
  config.idTokenSignedResponseAlg = "PS512";

  const jwt = await create(
    {
      alg: "PS512",
      typ: "JWT",
      kid: testJwks.keys[4].kid,
    },
    {
      iss: "aaa",
      aud: ["xxx", "yyy"],
      azp: "xxx",
      exp: Date.now() / 1000 + 5,
      iat: Date.now() / 1000 - 3500,
      auth_time: Date.now() / 1000 - 3500,
      nonce: "nonce",
    },
    RSA.importKey(testJwks.keys[4]).pem(),
  );
  const token = new IdToken(jwt);
  await token.validate("nonce", new ValueBasedJWKsProvider(testJwks));
});

Deno.test("HS256 valid", async () => {
  discovery.issuer = "aaa";
  config.clientId = "xxx";
  config.clientSecret = "secret";
  config.idTokenSignedResponseAlg = "HS256";

  const jwt = await create(
    {
      alg: "HS256",
      typ: "JWT",
    },
    {
      iss: "aaa",
      aud: ["xxx", "yyy"],
      azp: "xxx",
      exp: Date.now() / 1000 + 5,
      iat: Date.now() / 1000 - 3500,
      auth_time: Date.now() / 1000 - 3500,
      nonce: "nonce",
    },
    config.clientSecret,
  );
  const token = new IdToken(jwt);
  await token.validate("nonce", new ValueBasedJWKsProvider(testJwks));
});

Deno.test("HS512 valid", async () => {
  discovery.issuer = "aaa";
  config.clientId = "xxx";
  config.clientSecret = "secret";
  config.idTokenSignedResponseAlg = "HS512";

  const jwt = await create(
    {
      alg: "HS512",
      typ: "JWT",
    },
    {
      iss: "aaa",
      aud: ["xxx", "yyy"],
      azp: "xxx",
      exp: Date.now() / 1000 + 5,
      iat: Date.now() / 1000 - 3500,
      auth_time: Date.now() / 1000 - 3500,
      nonce: "nonce",
    },
    config.clientSecret,
  );
  const token = new IdToken(jwt);
  await token.validate("nonce", new ValueBasedJWKsProvider(testJwks));
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
  findJwk(_kid: string): Promise<string> {
    throw new Error("Method not implemented.");
  }
}

const testJwks = {
  "keys": [
    {
      "kid": "RSA256-1",
      "p":
        "-T7Ba-NeYEoxNFPfI6IVLxPjsVCi2pTT7LsT58QkrWr7W5z1MAsTtqM2mbGsPUtfpt0DaxAwG6l91oA3pGCNMbzU2zNZQ8BPoJGHOqhFmyK4qQG5SKgGskLUgZR_fmzKd6c8Peodb0__gjJ5Sjywq0oIJvOQr86SUnX2-uvH7b8",
      "kty": "RSA",
      "q":
        "yAnz8samxXlxb3FL6RzaStIyEwyB4ao4MDbcHtNkDxLyM5TZlk1Ub9YNUuH-qr0XGhtxfwb5ey_7hbXsw8_JG0Z1czuA01l3PU85yDWs-VMybm9gvuag-Tr_mOYr1_ZrYvJbHzM8CngDRO7FpIDo5zEMnI7aVclLRNYrNA8-Kjk",
      "d":
        "N73NKTTp5wzGDIVFTJ6XuHIh--J7jmXKgt5SGhf_nMjmtO_oU9eSAeBH1DoBvKuvIu4KRi9nzsJdzBOt3VVtU2qPQZgwqED2253kKedbOHBlIN5AUyDUuqVbW13P6-Gi3tBVxu8byKmRPxsHTckzerAElcB9bj9sH1mPVpVPCchNmkutwEfUOmnhmTLwgBCRDGNkdIdwUASWKZc2dZBpvfB2n3yaB96fnPLMRuNjiAIj5s_0g6zpgnW4YUssjHdIdW90acI37cuxxl-Vfzv9nthUouIkUu8IAbWXuyCJQRx3ZbT-0KA5R-RRXYLJU2gMwhtOlENFhAydcsDY4D5X0Q",
      "e": "AQAB",
      "use": "sig",
      "qi":
        "hMuTgVTiFEnHo3kMU4xQRrzUhTApwvSh7GGVEqpwh4JM7w6ZWfFn5LeBLNETVjROsVR-BuDZ8Thg8XroXflXN7_mdD4WlEQoldEtBDPthP2A1m86D-3BgSB8NpH9U1UIm8VjlT7r0pqaEGlOrpVsIAB1LprD5EeBqEMYydK7XuM",
      "dp":
        "We24oBKzVI6wXi78zcCHYCsO9kUf3TnhlQKS1gbBLQjylEV3edQlUrpk0uN2P89YPb50o0Z99R0cWC5-5QIpL47wRf6q8HUMxeR8JD_ejXDjq6cBkSN-9waB4hcQQS9DhhSC-dvkrurwR6uqc4yeOc9GTbeHtscTqEkDydkUk8U",
      "alg": "RS256",
      "dq":
        "hwGoohaOYcK321XkvLzbWxoH77FGS059w5SS9T8ITeAklMmGHJmuPhiCP4kFPqiF2fnhnLDRWeGlaLXCyNkIyp7AD_h91qaQAlHhFo2bY15SMBR9f_nZdLvr236k4omOKmaVNzZ19D7RPgnEXGUgS0BgWZ1UIAfOA_RjjiwncYk",
      "n":
        "wsK31AbB4ulDbSK7eH-ykvZUSrCEyDXzQvS55QhOyc9SzTkplS__sTLx4YjuqY7Mg3nTs23TyC5bZQffzdHEzjIuGxkMRpxekBu67-b1CaTg4rdP5ucsAihYH3YkoLA1gdol2akZCpiIDgi9js7zrJM6LeZpe9CXUJ2lg55o8Ux4gZIk8ffHeMo0xSlvaLTwvzwI2YE6L0880O15ZdpQ5N2juIhUY5R8gZ-oMeMWl7YYEqxKLsQd_FyyW_8QMZcn_reH-hYR6iAsx4J1pWxY9ziXw_UEsTCaEqS5BuUaHLMjVXNy3WF46M1VuWz-P2ZWxZnz2_nLBPUulFmzEcdFhw",
    },
    {
      "kid": "RSA256-2",
      "p":
        "_FrZmtOSqA6Ano5UuMtBaRspaBhquJl_OzDgooHJUfiMlT4LQEr3PKFuElZe-N48kHTno5Wwqja_RtZ0pcaB_56vrt-LDV7yfc407shUFxApHrrLhpr-UhQ0cAFmG-qcE8hzQdCJ55S0dWytueWUS6_LCT-8KMhFPRgf1v8exok",
      "kty": "RSA",
      "q":
        "3KnTdnl-ejiWs8y1mnP_GxjeEDzHv5eRnIoWQ88MAzxQ2agv_Y5Rqwig99ZBDt_Kyo5lQYB3uY341rc1MbLrT6KXw1IUyUWZSkCxj0nxIh7TuBz5OBJmMJkmTMcaTLbeOc8DCp3bmUisO4wscP81YVPk186SGztefQRk1DbJdp0",
      "d":
        "Zql0NwTFDIK6_lQKIBH0LPgSUnPSDLyr_2o8XbD4y74yTwFpYnd9JlaIx6hXelQagiP0-kRBESDmtI1VPPqVN25ws2y7vKnlno2QnTSxFE6ts681_5uSRtdRlhzQN1yAwn9y4eMvfA29sR7tgNfo1gqzQys32RIzmdY91ijlPQd5RxDB1zlsVowLTzkZrSGmjOBQ8lfmRgm1LIO-sFvwFdN8ARNEjYYE9kW985sUmvkRi3zHQg0F_NsT-X6fWVoaJiWKteaEtkXYfBUYbmoKW22KZvFaBELcerRRbLz8OMIYxMqacxn2QtTa-I7lwkUKfT2IkMWVO_1AgoWXABXWoQ",
      "e": "AQAB",
      "use": "sig",
      "qi":
        "XZZbVp9du2U0K4H5ky24Tbu_dF4-dN1F8WT6FExgaU982Zj2hwRNZY9cw1qkieLE5Z5IWkZk-mj_eDFvAcgvod0wq3bgXYKTwrNoC4DpK2yBC3DLuR7mrpebZv8Xz8MGat7QkDtbsnXQrTewtMC0azxRVmKMRe-3Cfx0hJzCSs8",
      "dp":
        "Ko9z9c3LBTb08EjW9xeon35qPFkp3ppcv_HdYOr8tityIlWFdkFuczZSpxsUB2sL0d01l_xOAFcdaWgP4kmZcTAlNxwSip3Bzf_yI3d73yvlk34zhy8qx1MLCPzjaL_ntNpwvd_a8ki9KrS6lAipOx6Z4qRyKnqkWspvzEXYvek",
      "alg": "RS256",
      "dq":
        "dv8mSEewixylOIT2kjpnoidA6aS9W3bTUYWuCBdJtRz7xMTMTIJJTGC03bIvF2RcKeuscyxiZDBJtxDJoOmJuEJIcU58YyYjSkWk-062uN3C8xC83R4e-ao9Wz4r0p7zLF2UmE8Us47bQqmO9cjK8peZWz_Mzt6vT9_kuARrlIk",
      "n":
        "2YV7bmAGPAkqjuTQxFodzZCs5m9jnLRmfylwRRpqD5Fo9s1xMk2uD7TGp2BbITGKrK84881omfV8y-7VNHJVP3gzVGQBkUpqjiI1Rhq4BxUpvcdz0dSH63zN_z3rSy5oQkei2dZyZCwUFfzLPEoSaBCQUwRi_TpQO4osWUa3tEzAocW21KNRXuOgJgZJEaScD3iInjxhrdmoJpD-M9qw_8Js9YD3yV2VaB4Wl4hi1XCx1F35tcwGQnsf5n3b8YOm57EcXLBWq4T56Cm1xr47Y5NaoAQeF_4lDMn3WRycSlyxthzuWZfC3jbvTkO0IsKuIlGIqmBsobU6RVrxbPPoBQ",
    },
    {
      "kid": "RSA512-1",
      "p":
        "-8K0B3ebTxjSYQR_wu4RClh4aJ3GgyVQfiaYETKmdm_vWWoiVrkCQTvjO4OXalps3UAa46UZ0n0hWXSqrgYkgGaAZu4iSVyPE9PGPO_wnzEGWtjs2YaCgpCHF75dlo21FZ3WdlPy5L8NS9gWiQ61-SjcsULdyWD3E_Gw-VZYNHU",
      "kty": "RSA",
      "q":
        "2TqitO_gWnhNYo6nCvOyt8P5Luk-8sK_CwvKhHf7V1USZu4yh0vvwhnZQo4uJ4DGwVmZmDnxYvKM6cfBPCLod0TNKti9Nx8dbwoFYik3cMFo4kyFZhhUlMhXo2wCYLwpa928jb2m-eWGbhQaz8N55xlH_1ABwdNbMaVxCXwc5EM",
      "d":
        "eRGkj6-w5vqj_cIsIRuZgKF02XxHXRCYpe8FjNYS3j9X-p3x0b6nVFjND8_PZqalqQUZcqBRP_vqbt4gPZzc5f120mJHxT_1gNCrGdaUU258vGeVjSdX9PjfCpCHVeJmBOQnoVLk3OgXPl95riLC-Lvju-mMZX4uXMpiFWLzYsNswUUUZW8NKTApfN3DrvRZxpkIv2V_W4VlfkozuNP69sDFPxmxUmOaA-q_0L_lSlBklnq0KifltX6mlYQw9sLsBZ3Xvt9zy3Uysa9yFSGyFQgIqfUyJPkTRS_SrxBLPYzKGwEYIZY-P6rKnm4LY8lsMepxmYWNoHCQTUgtgiT0CQ",
      "e": "AQAB",
      "use": "sig",
      "qi":
        "40-i6UMoFxyx20AQ0FHTmfz_J71DVApZOJGxaQTNhKRPDQAYrhlqpk7jurkVJ8wJGeUKZMKj7XkQmyG5udrJIpP2uguQrNzlpxXJHy9YP4nnkNI5iXdYRg0CrcfqfSjmOgQQoQHvDN5DxEISYo8BNEF7uLauFt2htsMtpgvcj6o",
      "dp":
        "C0BzbVYCIfHZDS73Ss37AvxbPUm34oqbY1f0OeiKmgZ8qwFcUYXpPOMhT7qc3Mr3zJed3Ai387lV8TqOmkJ6BScPnAoOjDrPxjITzQtoNKUrRIonY71oPc-Zygze_-iLbFDmkdlEpMaJIJeiwjNfHKif3GhBo0trH4AQycP7IzU",
      "alg": "RS512",
      "dq":
        "wQJeSxHPb9LwPx-swAhjxO-1Wb8YlS3__NqPKEBK6__Eh_wgnSIVd4rsBTy7OZIsBuOLmzvwhBAqsBUyVjJWBpL1EJrfFDjrOBvZSKyCfAb9IAUJifsYO9H-PE_dlQHac-Lig7X8xJDxbqEiaXOvvmwyEmGODh-zKVtsIhdKvG0",
      "n":
        "1aG0ukTOd5WZEWCkH3TJUnopauRjEgms4NYG7tr6PzF74aFk-2tt7IzB9qVSXQ0XXuV5MQ2q0psrlm-dDBqtlybG2hra1qYsWkf49Y4wjUqLkY3pmp2BN_6mLY62MH6vsFX_Dxr8a9zgRrzDNgVQoje1qxPcH8Bkw3QEKVzwX1aPXyh_a-zNblbOc5zPasGiKc6orCPT8W0VRiawBHD2BVPGHsVDAtJn9t0807cYb84XD_phOu4e7XQTTkBUMJAXfwmW9w3Wwf_iwZPtYA2DZaVg58GOWz0TmW8lI6eFS_qAWdRIicUniDUJdyHtRhl2Aq4gOkFkk_HHogpTkJnunw",
    },
    {
      "kid": "PS256-1",
      "p":
        "29WhNmzUenAKE_K_gBYBVcIBYQq-Kas7abSwqAidaw6e5UFlJatl2-SEdmRZb_Fw-_kKJEd8pXahYelejKl7eRrLi7E9hbpCheNFa9cQ76mfx4RR85gf2KAqurE0X7rdavorgX1bob8-7DQyiHemCAQrcrR-IxvUbERPZO-jdsE",
      "kty": "RSA",
      "q":
        "tOKULS8YF2MmMTPdK_2apzbqOA-YZQU1HXV4UDybmjGkTgFl0HmLP5wtqhdfJlg99HGefZKtP5oYD6idhWc0vyj_z9juOTrNE2aK4L4ECFXegIUMVjXgyRJBSjfCSBp1qWvR7IfS73xNZ6x-JlcGKu5D2yS6hLwcad5-xZXCXH0",
      "d":
        "ccQmIClszCEJ87IGNLUawV8-3JzF-k-WcI4bPLcWjV1AQvyRRHbNrGvm1lpVCokGmcxLdy50xGFdU4UiqzPf_rBsBIQvMVaFX-uYVUwn--TCayH5aCsnmcR8Imie1wxQ7RtxqWzl0qTn0qvWbl9STL716f75MdY-AIw8KyvLiNQWp9v7YDHehMK9Ol60fkGzmrUjn_iwoSMji8WUd5ZL8Wi_DiG7zjo68x72r6hUWR-qzu9Bex9I6yWW-IK7c1N_49nvILRJ7cRoDc8gEMAGUJqGvDAp_NsIyMdHxXkwbyLd9cFFK35grof00cZVLTGzjjGD_sSp81_QYbyWTGiAAQ",
      "e": "AQAB",
      "use": "sig",
      "qi":
        "QIVNkozqytQLSK0hWGpfV7jc4EUWvK4Akro2D9IDpJn9k3tN-m3DaJDCHF5xyoMyXNVwfHdy5Uy34wmwCgICEWhs7s7pgWbuP-kY6MTX4mNf-HVaJHIUSGs-ziWO4l0U4BD0uT4su8-f3-9IksGyo8_i9aorKshgnnwkFYswypk",
      "dp":
        "gpCjKzwABqg8lBR9AIoRSOns_8Htp7n3k5Spx2M2e7s3TFpGxNTDrpJOyjJXnFD-FemXyGxc77lBqHF-onSWzRrJAbLHI4G4uOR--snFWVKZf1prgg47--FE_5T30lOd5kenR0U5AxwfNxLZYIwPpHs1gu8Ia7m_tH3t2bkqkQE",
      "alg": "PS256",
      "dq":
        "XHS7vGSn8bxSFzAlSojz9ahSC5mdEXWZ8pbKimiQOD5LdzurqOWXUUoo5RnRHq5X7IvusMy6FRpUVhyfd0KLaXIxXzHIgiQWEmaFcd5t_Ty24AYhiic74EqeaKsbePNdVN2xjS7XmGV2wxkd2cb9dhAXSvn5BEOKWmrJbYDguZk",
      "n":
        "m1THMOTDL9xHG6Bk5l__RDwTbxSqG2vzXxXogXaLoQtWMBxwTd32oWqZRUwB5z42zI83p-dRKsjiPqXV7rZU65uI0M_Oc2axGdx1w8dS_KeV7hp6QF2cA_1i2k7ayvtvPVXWuYHJub4X2TFfB8vHkt2KHfpikHdhZsvCLD7BebB-8ti7_ngrCJ0qguvFJf0xWQ1hlAD4o-poseOCfst4qayW4bAMljYbD9pJLg_9YNSBu1o2judbOOiPFeBbvXuWFdoi2YySFTkEOQqSCwNXqPhDCak-cIEAx1Q20A0hOMFmcyCPXknwXN_NMDHqIf6ij_y2jdU0FsxVdijrFMBYPQ",
    },
    {
      "kid": "PS512-1",
      "p":
        "-8pvtCMfBsJmFOlVj-0vQ0n0ALL7fC8DTPmet2TSxheaiXkQMnbgnIorJ2_VQ4TmPvYRqk1WX_UTrEHp4h9HRVPWyGx4xehWDSTyeumQBPTRrcl5cKfHdSbaXd41hczkH4eCEEMaZ_QErHSnouaBXLBAQZmb9xo1Dp0Qs9R89GE",
      "kty": "RSA",
      "q":
        "tbboQb--TNk93KpWTO_smM8TRnQ-bKwUBjQ-F5BCewFHnoLiVHdu7EratGydIefjKl_irMxzlQemVCzqPcG0S6rG_2TzUtFeISJm0NqptavEx_QMaf-Ydoc77OnfIQTnUmBcIDZD1D-MyGLGquKJRKUQIAMlAV5Y4LSosrXtfJU",
      "d":
        "qSsL5nNs0Zp5Trv9n-d1PhY7q0gcasOVXc3ls1sp4dlosDndjaG_8kRaSsV2wHlux91eD08RmR0kWA6filb-gyzATECnMKw-HvQTomDJrINPh2NFg1CwZ0R6-TOOmBPy3ls_oqQYN-Re9MaNl53GFZCO_Gh04yMX0BoW9InJCGLS9RjyW33Kck3cjnpqZ1liNEoAzFZYAWHnV6y6ZoMzPnuV5EvK9TjjEfjF-RW2F7ovp1EESdLkkWyXwGh4zSJ6n9PUwFlrA6PqKN52uouvP8lYz5VMj82o9I-WIJpzKQznCpd48nLslLc6Dj4CfkLUXtF74jGGzwkNkj1tQURYAQ",
      "e": "AQAB",
      "use": "sig",
      "qi":
        "6dusQJULNj-NVyuRJ3GO2aJU6XpQEZ_O694bkroYvLfYH0Mz9tVg6GdtSx14DlMw6rxJbwscGzfC4vxptVdop19j-zZhh4f_XXBLgxgEXG3iUCElyXZFg_qzSfE0cfJ9Yj2Qc8H-OQE88ICbIkezl6ciYEaWq4H5EQua6VhDR4o",
      "dp":
        "2M1QLX1oQ7uzhiH7qHgEEB5nWQrD_APHBcqR3TuVOTgtul1hkvJFKMTXr5ddvEt8rY3XXBpHW0x86f-_URK5nXo5IE42F8KcBalgmHDvrzTWLpuiU1xEJB2WPOkOkO0BKBzX4wTEgenc9Fll1qA_lv2z9kg7wSLxuGmJbi5ygUE",
      "alg": "PS512",
      "dq":
        "oR8jZVkc5YsinQy0JNgAE6ZY0vmzeCxEPRQJkl8pc2O5G0W2ZWrZAc-FiMFdunigJiyLEujd-2CjDLQeps-gjA9LD511WxOlwP995uZb4GgDvcAZWct2ZnKWogTlAaQVcCdcyHsVPZdzvyJGQbNIP4OUfq4LG-GKMQQ_KObDQtk",
      "n":
        "sroHVeceuZNb4ucGhSNp3qLOJzzYhpHthGeM2RyUbJFPeXDFVHM2jsaKEOcc4TsHM-JPjY6yDURUvQ6wqxygsasZZJF6sKVE6nuviRjxdlBoouicyI9eD2e-OV_Xoyv0lhRUPwIoZOFj4DIxYhojeNz05PVO9EeOX_M4HsXzAEDuawIm1UNNVeFpzZvaoD6QrnCNK_GfysGnRoI5Jc23sd8BOUvt4GTlhIO-4aU8ebrZZUa6Y6P7m6qniygWU9stbiKnFY7gIAvtF-iUkbjgxjHMioohU9KFAwmXpEtoCfyjU9JRh77mU86HjPtZD6ZoKF8Vj3iShbGkr3eABeY4dQ",
    },
  ],
};
