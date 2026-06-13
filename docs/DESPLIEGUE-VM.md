# Despliegue en la VM Ubuntu — Paso a Paso

Guía operativa completa para levantar CTFHL4-INSANE en una VM Ubuntu 22.04 que
simula la VPS. Incluye los dos puntos que más suelen romper: **preservación de
la IP de origen** (para el gate VPN) y **dnsmasq vs systemd-resolved**.

Requisitos VM: 4+ vCPU, 8+ GB RAM, 40+ GB disco, Ubuntu 22.04 o 24.04, acceso root.
Una sola IP pública/alcanzable para el puerto VPN (1194/udp).

---

## 0. Preparación

> NOTA Ubuntu 24.04 (Noble): el paquete `docker-compose-plugin` NO está en los
> repos de Ubuntu (solo en el repo oficial de Docker). Usa el repo oficial:

```bash
# Utilidades base
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg git make jq

# Repo oficial de Docker
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Engine + compose v2 + buildx
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

sudo systemctl enable --now docker
sudo docker run --rm hello-world      # verifica engine
sudo docker compose version           # verifica compose v2

git clone <repo> && cd CTFHL4-INSANE
```

Alternativa rápida solo con repos de Ubuntu (compose v2 viene en `docker-compose-v2`):
```bash
sudo apt-get install -y docker.io docker-compose-v2 docker-buildx git make jq
sudo systemctl enable --now docker
```

---

## 1. VPN (OpenVPN)

```bash
cd vpn/scripts
sudo ./setup-server.sh <IP_VM> 1194 udp

# Añadir directivas extra al server.conf generado:
sudo bash -c 'cat ../configs/server-additions.conf      >> /etc/openvpn/server.conf'
sudo bash -c 'cat ../configs/server-ban-additions.conf  >> /etc/openvpn/server.conf'

# Copiar los hooks de ban al lugar que espera server.conf y darles permisos:
sudo mkdir -p /etc/openvpn/scripts
sudo cp on-connect.sh on-disconnect.sh ban-team.sh unban.sh /etc/openvpn/scripts/
sudo chmod +x /etc/openvpn/scripts/*.sh

sudo systemctl restart openvpn@server
ip a show tun0    # debe existir antes de levantar Suricata
```

> El `redirect-gateway` de `server-additions.conf` te vuelve el gateway de
> internet de los jugadores. Mide ancho de banda con carga real (40 personas).

---

## 2. Plataforma + SIEM

```bash
cd ../../infra
cp .env.example .env
# Genera secretos:
sed -i "s/^MASTER_SECRET=.*/MASTER_SECRET=$(openssl rand -hex 32)/" .env
sed -i "s/^JWT_SECRET=.*/JWT_SECRET=$(openssl rand -hex 32)/" .env
sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(openssl rand -hex 16)/" .env
nano .env    # revisa GRAFANA_PASSWORD y DISCORD_WEBHOOK_URL (opcional)

make up        # build + arranque
make seed      # crea equipos + retos; imprime credenciales y guarda credentials.txt
```

---

## 3. ★ Preservación de IP de origen (CRÍTICO para el gate VPN)

El backend solo acepta requests cuya IP esté en `10.10.0.0/16` (gate VPN). El
diseño YA preserva la IP del cliente porque **nginx no publica puertos al host**:
vive en `10.10.100.10` y la VPN enruta `10.10.100.0/24` hacia él, sin NAT. nginx
reenvía la IP real al backend vía `X-Forwarded-For` (`TRUST_FORWARDED_FOR=true`).

El único punto a habilitar es que el host **reenvíe** tun0 → red docker de la
plataforma. Docker pone la política de FORWARD en DROP, así que añade en la
cadena `DOCKER-USER` (se evalúa antes de las reglas de docker):

```bash
# Descubre el bridge de la red de plataforma (subnet 10.10.100.0/24):
BR=$(docker network inspect infra_net_platform -f '{{ index .Options "com.docker.network.bridge.name" }}')
# Si sale vacío, úsalo por id:
[ -z "$BR" ] && BR="br-$(docker network inspect infra_net_platform -f '{{ .Id }}' | cut -c1-12)"

sudo iptables -I DOCKER-USER -i tun0 -o "$BR" -j ACCEPT
sudo iptables -I DOCKER-USER -o tun0 -i "$BR" -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo netfilter-persistent save
```

**Verificación:** conecta la VPN, entra a `http://10.10.100.10/`, haz login. Si
da 403 "fuera de VPN", revisa que el backend ve la IP `10.10.X.Y`:
```bash
docker compose logs platform-api | grep -i forwarded
```

---

## 4. Firewall (aislamiento entre equipos) + bloqueo IA

```bash
cd firewall
sudo ./setup-nftables.sh         # aísla 10.10.N.0/24 -> 172.30.N.0/24, DROP+LOG inter-equipo

# DNS interno con sinkhole de IA. Antes, liberar el puerto 53 de systemd-resolved:
sudo sed -i 's/^#\?DNSStubListener=.*/DNSStubListener=no/' /etc/systemd/resolved.conf
sudo systemctl restart systemd-resolved

sudo apt install -y dnsmasq
./gen-dnsmasq-blocklist.sh
sudo cp dnsmasq.conf /etc/dnsmasq.d/ctf.conf
sudo mkdir -p /var/log/dnsmasq
sudo systemctl restart dnsmasq

# (Opcional) bloqueo por IP de proveedores IA:
# editar ai-ip-blocklist.sh con los CIDRs reales y: sudo ./ai-ip-blocklist.sh
cd ..
```

---

## 5. Suricata (IDS — requiere tun0 ya activo)

```bash
make siem-up
docker logs ctf-suricata | tail        # confirma que escucha tun0 sin errores
```

---

## 6. Retos por equipo (aislados)

```bash
# Uno por equipo (crea su red 172.30.N.0/24 y lanza los 6 retos con su flag):
for n in $(seq 1 10); do ./launch-team-challenges.sh team_$(printf '%02d' $n); done
# Detener los de un equipo: ./launch-team-challenges.sh team_03 down
```

---

## 7. Entrega a los equipos

```bash
# Un .ovpn por equipo:
for n in $(seq 1 10); do
  sudo vpn/scripts/gen-team-cert.sh team_$(printf '%02d' $n) <IP_VM>
done
# Entregar a cada equipo: su team_NN.ovpn + su usuario/contraseña (credentials.txt).
```

---

## 8. Acceso del admin al SIEM

Grafana escucha SOLO en `127.0.0.1:3000` de la VM. Accede por túnel SSH:
```bash
ssh -L 3000:127.0.0.1:3000 usuario@<IP_VM>
# luego abre http://localhost:3000  (admin / GRAFANA_PASSWORD del .env)
```

---

## 9. Smoke-test

```bash
cd infra && ./smoke-test.sh
```

Luego corre el **checklist manual** de `docs/INTEGRACION-Y-PRUEBA.md` (nmap visible,
aislamiento entre equipos, bloqueo IA, ban por 3 desconexiones, anti-cheat).
