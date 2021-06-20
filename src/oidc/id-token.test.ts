import { assertThrows } from "https://deno.land/std@0.99.0/testing/asserts.ts";
import { IdToken } from "./id-token.ts";

Deno.test("invalid jwt", () => {
    assertThrows(() => {
        new IdToken("aaa");
    }, Error)
});
