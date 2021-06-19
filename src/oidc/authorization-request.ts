import { v4 } from "https://deno.land/std/uuid/mod.ts";

export class AuthorizationRequestBuilder {
  uri: string;
  scope: string[];
  responseType: ResponseType;
  clientId: string;
  redirectUri: string;
  state: string;
  nonce: string;

  constructor(
    uri: string,
    scope: string[],
    responseType: ResponseType,
    clientId: string,
    redirectUri: string,
  ) {
    this.uri = uri;
    this.scope = scope;
    this.responseType = responseType;
    this.clientId = clientId;
    this.redirectUri = redirectUri;
    this.state = v4.generate();
    this.nonce = v4.generate();
  }

  build(): string {
    const url = new URL(this.uri);
    url.searchParams.append("scope", this.scope.join(" "));
    url.searchParams.append("response_type", this.responseType.toString());
    url.searchParams.append("client_id", this.clientId);
    url.searchParams.append("redirect_uri", this.redirectUri);
    url.searchParams.append("state", this.state);
    url.searchParams.append("nonce", this.nonce);
    return url.href;
  }
}

export enum ResponseType {
  CODE = "code",
  IMPLICIT = "implicit",
}
