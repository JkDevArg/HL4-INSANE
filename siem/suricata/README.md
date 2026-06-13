# Suricata IDS — CTFHL4-INSANE

IDS **pasivo** sobre la interfaz VPN `tun0`. Detecta nmap, escaneos de
puertos, fuerza bruta y firmas de exploits web. Las alertas salen a
`eve.json`, que Promtail recoge y manda a Loki (`job=suricata`) para verlas
en el dashboard de Grafana `ids-alerts.json`.

Contrato (ver `docs/ARCHITECTURE.md` sección 3):
`suricata — host (tun0) — IDS pasivo sobre VPN`.

## Archivos

| Archivo | Qué es |
|---|---|
| `suricata.yaml` | Config mínima: captura `tun0` (af-packet), salida `eve.json`, carga `custom.rules`. |
| `custom.rules` | Reglas locales (SID 1000000+). nmap, scans, brute-force, exploits web. |

`HOME_NET = 10.10.0.0/16` (toda la VPN, ver plan de red sección 2).

---

## Opción A — Suricata en el HOST (recomendado)

Suricata escucha la `tun0` que crea OpenVPN en el propio host del servidor VPN.

```bash
# 1. Instalar (Debian/Ubuntu)
sudo apt-get update && sudo apt-get install -y suricata

# 2. Copiar configuración y reglas
sudo cp suricata.yaml   /etc/suricata/suricata.yaml
sudo mkdir -p /etc/suricata/rules
sudo cp custom.rules    /etc/suricata/rules/custom.rules
sudo mkdir -p /var/log/suricata

# 3. Validar la config y las reglas SIN arrancar (test mode)
sudo suricata -T -c /etc/suricata/suricata.yaml -v

# 4. Arrancar en modo IDS sobre tun0
sudo suricata -c /etc/suricata/suricata.yaml -i tun0

#    (o como servicio, fijando la interfaz)
#    sudo sed -i 's/^AF_PACKET_IFACE=.*/AF_PACKET_IFACE=tun0/' /etc/default/suricata
#    sudo systemctl enable --now suricata
```

Las alertas aparecen en `/var/log/suricata/eve.json`.

---

## Opción B — Suricata en CONTENEDOR

El contenedor necesita ver `tun0`, que vive en el **host**. Por eso se corre
con `network_mode: host` + `NET_ADMIN`/`NET_RAW` (capturar paquetes crudos).

```yaml
# Fragmento para docker-compose del stack SIEM:
  suricata:
    image: jasonish/suricata:latest
    container_name: ctf-suricata
    network_mode: host          # necesita ver tun0 del host
    cap_add:
      - NET_ADMIN               # gestión de interfaz
      - NET_RAW                 # captura de paquetes
    command: ["-i", "tun0"]
    volumes:
      - ./suricata/suricata.yaml:/etc/suricata/suricata.yaml:ro
      - ./suricata/custom.rules:/etc/suricata/rules/custom.rules:ro
      - suricata-logs:/var/log/suricata   # compartido con Promtail
    restart: unless-stopped
```

Comando directo equivalente:

```bash
docker run -d --name ctf-suricata \
  --network host --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$PWD/suricata.yaml:/etc/suricata/suricata.yaml:ro" \
  -v "$PWD/custom.rules:/etc/suricata/rules/custom.rules:ro" \
  -v suricata-logs:/var/log/suricata \
  jasonish/suricata:latest -i tun0
```

Promtail debe montar el mismo volumen `suricata-logs` (o el path
`/var/log/suricata`) para leer `eve.json` (job=suricata).

---

## Verificar que "se ve" un nmap

Desde una máquina conectada a la VPN, contra otra IP de la VPN:

```bash
nmap -sS 10.10.100.10        # SYN scan   -> sid 1000004
nmap -sN 10.10.100.10        # NULL scan  -> sid 1000001
nmap -sV 10.10.100.10        # version    -> sid 1000005
nmap -sn 10.10.0.0/24        # ping sweep -> sid 1000006
```

Y observa los hits:

```bash
sudo tail -f /var/log/suricata/eve.json | grep -i '"event_type":"alert"'
```

En Grafana → dashboard **IDS / Suricata Alerts** verás los `[NMAP]`,
`[SCAN]`, `[BRUTE]` y `[WEB-EXPLOIT]`.

---

## Añadir reglas

Ver el encabezado de `custom.rules`: copia una regla, asigna un **SID nuevo
>= 1000000**, pon `rev:1` y un `msg` con su categoría. Recarga con
`suricatasc -c reload-rules` o reinicia el contenedor. Valida siempre con
`suricata -T -c suricata.yaml` antes de desplegar.
