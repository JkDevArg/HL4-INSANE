# Ban por 3 desconexiones de VPN

Implementa la politica **6.2** del contrato (`docs/ARCHITECTURE.md`): contar las
desconexiones *limpias* iniciadas por el cliente y, al tercer evento, banear al
equipo (revocar cert + bloquear login en plataforma + cortar sesion).

## Componentes

| Archivo | Rol | Disparado por |
|---|---|---|
| `on-connect.sh` | hook `client-connect` | OpenVPN al conectar un cliente |
| `on-disconnect.sh` | hook `client-disconnect` | OpenVPN al desconectar un cliente |
| `ban-team.sh <team>` | banea (Redis + CRL + kill + SIEM) | `on-disconnect.sh` o admin manual |
| `unban.sh <team>` | revierte el ban (solo admin) | admin manual |
| `../configs/server-ban-additions.conf` | directivas a añadir al `server.conf` | — |

El CN del certificado de cada equipo es `team_NN` (contrato sec.1), y es la
identidad que usamos en todas las keys y eventos.

## Flujo

```
conectar  -> on-connect.sh    -> ¿ban:team_NN existe? --si--> exit 1 (rechaza)
                                            \--no--> log + SIEM vpn_connect(info)

desconectar -> on-disconnect.sh -> ¿desconexion limpia del cliente?
                                       \--no--> log + SIEM vpn_disconnect(counts=false)  [FIN]
                                       \--si--> INCR vpn:disc:team_NN = N
                                                log + SIEM vpn_disconnect(count=N)
                                                ¿N >= 3? --si--> ban-team.sh team_NN
```

## Heuristica limpia-vs-timeout (lo que cuenta)

OpenVPN expone variables de entorno al hook `client-disconnect`. Usamos:

- **`$signal`** — motivo del cierre cuando OpenVPN lo conoce.
- **`$time_duration`** — duracion de la sesion en segundos.
- (`$common_name`, `$ifconfig_pool_remote_ip`, `$trusted_ip` para identidad/log.)

Decision:

| Condicion | ¿Cuenta? | Clase |
|---|---|---|
| `signal == remote-exit` (cliente envio *exit-notify*) | **SI** | `client_exit_notify` |
| `signal` vacio **y** `time_duration < 120s` | **SI** | `short_session_assumed_client` |
| `signal == ping-restart` (timeout keepalive) | no | `keepalive_timeout` |
| `signal in {sigterm,sigint,sigusr1,sighup}` (server reinicio) | no | `server_side_signal` |
| `signal` vacio **y** `time_duration >= 120s` | no | `long_session_assumed_timeout` |
| `signal` desconocido | no (conservador) | `unknown_signal_*` |

**Por que 120s:** el `server.conf` base trae `keepalive 10 120` -> el server
declara muerto a un peer tras ~120s sin respuesta. Una desconexion voluntaria
manda `exit-notify` (`signal=remote-exit`); cuando ese paquete UDP se pierde, una
sesion **corta** (<120s) delata un cierre intencional reciente, mientras que una
caida de red real se arrastra hasta el limite del keepalive. El umbral es
configurable con `KEEPALIVE_TIMEOUT` (debe igualar el keepalive del server).

## Falsos positivos y mitigaciones

- **Una caida de red legitima del jugador puede contar** (si reconecta y vuelve a
  caer en <120s, o si su cliente manda exit-notify al perder la ruta). Esto es una
  limitacion honesta: no podemos distinguir con certeza intencion de accidente
  desde el server.
- Mitigaciones disponibles, todas por variable de entorno (sin tocar codigo):
  - **`DISCONNECT_THRESHOLD`** (default `3`): sube el umbral si la red del evento
    es inestable.
  - **`DISC_WINDOW_TTL`** (default `0` = sin ventana): pon p.ej. `1800` para que
    el contador expire a los 30 min sin nuevas desconexiones limpias, evitando
    acumular caidas repartidas en todo el CTF.
  - **`KEEPALIVE_TIMEOUT`**: ajusta el corte corto-vs-largo.
- **Revision admin antes de ban permanente:** el ban via CRL es duro (requiere
  regenerar cert). Recomendado operar asi durante el evento:
  1. Monitorear los `vpn_disconnect` con `count` creciente en el SIEM (severity
     pasa a `warn` en el penultimo).
  2. El ban automatico bloquea login y corta VPN, pero **es reversible** con
     `unban.sh` (Redis) + `gen-team-cert.sh` (cert nuevo). No es definitivo.

## Configuracion (variables de entorno)

Todos los scripts leen estas (con defaults del contrato) y opcionalmente
`/etc/openvpn/scripts/ban.env` si existe:

| Variable | Default | Uso |
|---|---|---|
| `REDIS_HOST` | `10.10.100.31` | host Redis (contrato sec.3) |
| `REDIS_PORT` | `6379` | puerto Redis |
| `COLLECTOR_URL` | `http://10.10.200.10:9000/event` | collector SIEM |
| `EVENTS_LOG` | `/var/log/openvpn/events.log` | log parseable |
| `DISCONNECT_THRESHOLD` | `3` | desconexiones limpias para banear |
| `KEEPALIVE_TIMEOUT` | `120` | umbral corto-vs-largo (= keepalive server) |
| `DISC_WINDOW_TTL` | `0` | TTL del contador en segundos (0 = sin expirar) |
| `MGMT_HOST` / `MGMT_PORT` | `127.0.0.1` / `7505` | management interface (kill) |

Ejemplo `/etc/openvpn/scripts/ban.env`:

```sh
DISCONNECT_THRESHOLD=4
DISC_WINDOW_TTL=1800
```

## Estado en Redis

| Key | Valor | Quien la escribe | Quien la lee |
|---|---|---|---|
| `vpn:disc:team_NN` | contador (INCR) | `on-disconnect.sh` | `on-disconnect.sh` |
| `ban:team_NN` | `banned_at=...;reason=...` | `ban-team.sh` | `on-connect.sh` (rechaza), **plataforma (bloquea login)** |

> La plataforma (`platform-api`) consulta `ban:team_NN` antes de autorizar el
> login (contrato sec.6.2). Banear por VPN bloquea tambien la plataforma sin
> codigo extra: ambos miran la misma key.

## Formato del log parseable (`events.log`)

```
<ts-UTC> evt=<tipo> team=<CN> vpn_ip=<ip> real_ip=<ip[:puerto]> [campos key=value]
```

Ejemplos:
```
2026-06-13T18:00:00Z evt=vpn_connect team=team_03 vpn_ip=10.10.3.6 real_ip=190.x.x.x:51820 action=accepted
2026-06-13T18:05:10Z evt=vpn_disconnect team=team_03 vpn_ip=10.10.3.6 real_ip=190.x.x.x dur=42s signal=remote-exit counts=yes class=client_exit_notify count=3/3
2026-06-13T18:05:11Z evt=vpn_ban team=team_03 action=banned kill=mgmt
```

## Eventos SIEM emitidos (contrato sec.5)

- `vpn_connect` — `info` (aceptada) / `alert` (rechazada por ban).
- `vpn_disconnect` — `info`; `warn` al acercarse al umbral; incluye `counts`,
  `class`, `count`, `threshold`.
- `vpn_ban` — `critical` (ban); `warn` con `detail.action=unban` (desbaneo).

## Como banear / desbanear manualmente

```sh
# Banear (admin):
/etc/openvpn/scripts/ban-team.sh team_03

# Desbanear (admin): limpia Redis y REQUIERE regenerar el cert
/etc/openvpn/scripts/unban.sh team_03
/etc/openvpn/scripts/gen-team-cert.sh team_03 <IP_servidor>
# entregar el nuevo team_03.ovpn al equipo
```

`unban.sh` solo borra `ban:team_NN` y `vpn:disc:team_NN`. El cert quedo revocado
en la CRL (una CRL no admite quitar entradas), por eso hay que **emitir un cert
nuevo** con `gen-team-cert.sh` para restaurar el acceso VPN.

## Instalacion (resumen)

```sh
mkdir -p /etc/openvpn/scripts
cp on-connect.sh on-disconnect.sh ban-team.sh unban.sh \
   revoke-team.sh gen-team-cert.sh /etc/openvpn/scripts/
chmod +x /etc/openvpn/scripts/*.sh
cat ../configs/server-ban-additions.conf >> /etc/openvpn/server.conf
systemctl restart openvpn@server
```

Dependencias en el server: `redis-cli`, `curl`, y `nc` (opcional, para el kill
por management interface).
