# Firewall / Aislamiento + Bloqueo de IA — CTFHL4-INSANE

Capa de red que implementa la **sección 2 (Plan de Red / Regla de oro)** y la
**sección 6.1 (Bloqueo de IA)** de `docs/ARCHITECTURE.md`.

Todo aquí corre en el **servidor VPN (Ubuntu 22.04)**, como `root`.

## Qué hay aquí

| Archivo | Rol |
|---|---|
| `nftables.conf` | Reglas de aislamiento entre equipos (la "regla de oro"). Usa sets/maps para los 10 equipos. |
| `setup-nftables.sh` | Valida (`nft -c -f`), instala en `/etc/nftables.conf`, aplica y persiste. |
| `ai-blocklist.txt` | Lista (ampliable) de dominios de IA a sinkhole. |
| `dnsmasq.conf` | DNS interno (10.10.100.2): sinkhole IA + upstream 1.1.1.1 + log para SIEM. |
| `gen-dnsmasq-blocklist.sh` | Genera el bloque `address=/.../0.0.0.0` en `dnsmasq.conf` desde la blocklist (idempotente). |
| `ai-ip-blocklist.sh` | Tabla nftables extra: DROP+LOG (`AI_BLOCK`) de rangos IP de IA (placeholders a poblar). |
| `../../vpn/configs/server-additions.conf` | Directivas a **añadir** a `server.conf` (gateway total + DNS interno). |

## Orden de aplicación

> Hazlo en este orden. El firewall y el DNS son independientes, pero el
> sinkhole DNS necesita que el bloque esté generado antes de arrancar dnsmasq.

1. **VPN base** (ya existente): `vpn/scripts/setup-server.sh <IP_SERVIDOR>`
2. **Añadir directivas VPN** (gateway total + DNS interno):
   ```bash
   sudo bash -c 'cat vpn/configs/server-additions.conf >> /etc/openvpn/server.conf'
   sudo systemctl restart openvpn@server
   ```
3. **Firewall de aislamiento** (la regla de oro):
   ```bash
   sudo ./setup-nftables.sh
   ```
4. **DNS interno + sinkhole de IA**:
   ```bash
   sudo apt-get install -y dnsmasq
   sudo mkdir -p /var/log/dnsmasq && sudo chown dnsmasq:dnsmasq /var/log/dnsmasq
   ./gen-dnsmasq-blocklist.sh            # genera el bloque AI SINKHOLE en dnsmasq.conf
   sudo install -m 0644 dnsmasq.conf /etc/dnsmasq.d/ctf.conf
   sudo systemctl restart dnsmasq
   ```
   > Si el puerto 53 está ocupado por `systemd-resolved`, deshabilita su stub:
   > `sudo sed -i 's/^#\?DNSStubListener=.*/DNSStubListener=no/' /etc/systemd/resolved.conf && sudo systemctl restart systemd-resolved`
5. **(Opcional) Bloqueo por IP de IA** — solo tras poblar CIDR reales:
   ```bash
   # edita ai-ip-blocklist.sh (set ai_cidrs) — ver instrucciones dentro
   sudo ./ai-ip-blocklist.sh
   ```

## Verificación rápida

```bash
# Ruleset cargado y sets de equipos:
sudo nft list table inet ctf_isolation

# Sinkhole funcionando (debe devolver 0.0.0.0):
dig @10.10.100.2 api.openai.com +short

# Logs de bloqueo en vivo (kernel):
sudo journalctl -k -g 'INTER_TEAM_BLOCK|INTERNET_BLOCK|AI_BLOCK' -f

# Log de queries DNS que consume el SIEM:
sudo tail -f /var/log/dnsmasq/queries.log
```

Prefijos de log emitidos (para correlación en el SIEM): `INTER_TEAM_BLOCK`,
`INTERNET_BLOCK`, `SIEM_BLOCK`, `AI_BLOCK`, `FWD_DROP`, `INPUT_DROP`.

## Ampliar la blocklist de IA

1. Agrega dominios a `ai-blocklist.txt` (uno por línea).
2. `./gen-dnsmasq-blocklist.sh && sudo systemctl restart dnsmasq`.

El sinkhole `address=/dominio/0.0.0.0` cubre **todos los subdominios**
automáticamente (no hace falta listar `api.*`, `chat.*`, etc.).

## Limitación honesta

Esto es **bloqueo de red + log disuasorio**, no una garantía:

- **NO impide usar IA desde otro dispositivo** (un segundo laptop, el celular
  con datos móviles, etc.). El firewall solo controla el tráfico que entra por
  la VPN del CTF.
- Un cliente que ignore el `redirect-gateway`/DNS empujado podría intentar
  rutas/DNS propios; `block-outside-dns` y el bloqueo de internet directo lo
  dificultan, pero un atacante decidido fuera del túnel queda fuera de alcance.
- El **bloqueo por IP** (`ai-ip-blocklist.sh`) es secundario: los rangos de los
  proveedores cambian y muchos comparten CDN (Cloudflare/Azure) con servicios
  legítimos. La capa principal y más segura es el **sinkhole DNS** + el
  **registro de queries** para detección/disuasión vía SIEM.

El valor real es: (1) cerrar el camino fácil, (2) **dejar rastro** de cualquier
intento (logs DNS + drops nftables) para que el anti-cheat lo correlacione.
