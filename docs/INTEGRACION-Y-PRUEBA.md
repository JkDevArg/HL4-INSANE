# Integración y Prueba End-to-End (VM)

Orden de arranque en el servidor Ubuntu y puntos a VERIFICAR en la VM (hay
detalles de red que solo se confirman corriendo, no en Windows).

## Orden de arranque

```bash
# 1. VPN
cd vpn/scripts
sudo ./setup-server.sh <IP_SERVIDOR> 1194 udp
# Añadir directivas extra a /etc/openvpn/server.conf:
#   - vpn/configs/server-additions.conf      (redirect-gateway + DNS interno)
#   - vpn/configs/server-ban-additions.conf  (hooks de ban + management)
sudo systemctl restart openvpn@server

# 2. Plataforma + SIEM
cd ../../infra
cp .env.example .env && nano .env        # rellenar secretos
make up
make seed                                # crea equipos + retos, imprime credenciales

# 3. Firewall + bloqueo IA
cd firewall
sudo ./setup-nftables.sh
sudo apt install -y dnsmasq
./gen-dnsmasq-blocklist.sh && sudo cp dnsmasq.conf /etc/dnsmasq.d/ctf.conf && sudo systemctl restart dnsmasq

# 4. Suricata (necesita tun0 ya activo)
cd .. && make siem-up

# 5. Retos por equipo (aislados)
./launch-team-challenges.sh team_01
./launch-team-challenges.sh team_02
# ... por cada equipo
```

## Checklist de verificación (CRÍTICO probar en la VM)

| # | Qué verificar | Cómo | Riesgo si falla |
|---|---|---|---|
| 1 | **Source IP del cliente VPN llega al backend** | Conectar VPN, login. El gate VPN del backend usa `X-Forwarded-For` de nginx. Confirmar que nginx ve la IP `10.10.X.Y` (no la del bridge docker). | Si docker enmascara la IP origen, el gate VPN puede rechazar a todos. **Fix:** ruta (no NAT) de la subnet VPN al bridge, o nginx en `network_mode: host`. |
| 2 | **Aislamiento entre equipos** | Desde team_01 (`10.10.1.x`) intentar `curl 172.30.2.x` (reto de team_02) → debe ser DROP. Ver log `INTER_TEAM_BLOCK`. | Sin esto, un equipo ve los retos de otro. |
| 3 | **nmap visible en SIEM** | Desde un cliente VPN: `nmap -sS 10.10.100.10`. Ver alerta en Grafana → dashboard `ids-alerts`. | Requisito explícito del cliente. |
| 4 | **Bloqueo IA** | Desde cliente VPN: `dig @10.10.100.2 api.openai.com` → `0.0.0.0`. Ver intento en dashboard `ids-alerts`. | — |
| 5 | **Ban por 3 desconexiones** | Conectar/desconectar limpio 3 veces con un cert. Al 3º: cert revocado, `ban:team_NN` en Redis, evento `vpn_ban`, login bloqueado. | Falsos positivos por caídas de red (ver README-ban). |
| 6 | **Flag dinámica y anti-cheat** | team_01 resuelve un reto → OK. team_02 envía la flag de team_01 → 403 + evento `cheat_flag_share`. | — |
| 7 | **Máx 4 sesiones / equipo** | 5º login del mismo equipo → 429. | — |
| 8 | **Lanzador por equipo** | `make launch-team TEAM=team_03` levanta los 3 retos con su flag en `172.30.3.0/24` (.10 portal, .11 registry, .20 api, .30 crypto). | RESUELTO: composes ya usan red externa `${CHAL_NET}` + IP `172.30.${TEAM_N}.x`, sin puertos al host. |

## Gotchas conocidos (resolver en la VM)

1. **Preservación de IP origen (punto 1)** — el más probable de romper. Decidir entre nginx host-mode o routing de la subnet VPN.
2. **dnsmasq vs systemd-resolved** — Ubuntu suele tener el 53 ocupado; deshabilitar `systemd-resolved` stub o moverlo.
3. **redirect-gateway** — te vuelve gateway de internet de los jugadores; medir ancho de banda con 40 personas (10 equipos × 4).
4. **Suricata sobre tun0** — `tun0` debe existir antes de `make siem-up`. Confirmar que ve tráfico (`suricata -T`, luego `tail eve.json`).
5. **Composes de reto + CHAL_NET** — RESUELTO para los 3 retos construidos: usan red externa `${CHAL_NET}` con IP `172.30.${TEAM_N}.x` y NO publican puertos al host. Al crear retos nuevos, seguir el mismo patrón (ver `challenges/_templates`).
6. **Collector inalcanzable desde la red de retos (por diseño)** — los contenedores de reto viven SOLO en `172.30.N.0/24`, aislados del SIEM (`10.10.200.0/24`). Su `COLLECTOR_URL` no resuelve y los eventos directos del reto fallan en silencio (fire-and-forget). Es intencional: evita que un RCE en un reto pivote al SIEM. La visibilidad del reto en el SIEM llega por Suricata (IDS de red) y por los eventos de la plataforma (submits). Si en el futuro se quieren eventos directos del reto, enviarlos por stdout → Promtail (docker logs), NO abriendo ruta al SIEM.
