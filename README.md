# oidcrpsample

## Run with Keycloak

1. Up Keycloak.

```
docker run -d -p 18080:8080 -e KEYCLOAK_USER=admin -e KEYCLOAK_PASSWORD=admin --name keycloak quay.io/keycloak/keycloak
```

2. Client configuration.

```
vim .env
DISCOVERY_ENDPOINT={DISCOVERY_ENDPOINT}
CLIENT_ID={CLIENT_ID_FROM_KEYCLOAK}
CLIENT_SECRET={CLIENT_SECRET_FROM_KEYCLOAK}
```

3. Run application.

```
deno run --allow-net --allow-read src/server.ts
```

## Test

```
deno test --allow-read --allow-net
```
