# oidcrpsample

```
deno run --allow-net --allow-read src/server.ts
```

```
docker run -d -p 18080:8080 -e KEYCLOAK_USER=admin -e KEYCLOAK_PASSWORD=admin --name keycloak quay.io/keycloak/keycloak
```

```
http://localhost:18080/auth/realms/master/.well-known/openid-configuration
```
