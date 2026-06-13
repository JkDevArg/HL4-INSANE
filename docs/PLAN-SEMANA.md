# Plan de la Semana — CTFHL4-INSANE

> 1 semana. Objetivo realista: **infra completa + 5-6 retos INSANE sólidos**.
> 15 retos INSANE nuevos NO caben (1 reto INSANE = 1-3 días-persona). Se descopa.

## Estado de partida (ya hecho)
- ✅ VPN: setup-server / gen-team-cert / revoke-team
- ✅ flag-service (HMAC)
- 🟡 SIEM: Loki + Promtail (parcial)

## Día a día

| Día | Entregable |
|---|---|
| **D1** | Arquitectura (✅), orquestación unificada (docker-compose), platform-api skeleton (auth + equipos + DB) |
| **D2** | platform-api completo (retos, submit, scoreboard, gate VPN-only) + platform-web (login, lista retos, scoreboard) |
| **D3** | Firewall nftables (aislamiento por equipo) + bloqueo IA (dnsmasq + blocklist) + redirect-gateway |
| **D4** | Ban 3-desconexiones (scripts OpenVPN + Redis) + Suricata IDS (nmap/scan/exploit) + collector SIEM |
| **D5** | Grafana dashboards + anti-cheat flag-share + 2 retos (web supply-chain, crypto network) |
| **D6** | 3-4 retos más (api BOLA/mass-assignment, web SSTI/deserialización) + writeups privados |
| **D7** | Prueba end-to-end en la VM (2 equipos simulados) + hardening + checklist de lanzamiento |

## Riesgos
1. **Retos INSANE** — el cuello de botella. Empezar D5, no esperar.
2. **redirect-gateway total** — te vuelve gateway de internet de los jugadores; probar consumo de ancho de banda.
3. **150 contenedores** si se pre-montan todos → usar spawn por-equipo bajo demanda o límites de recursos.
