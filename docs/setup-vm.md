# Setup: VM Ubuntu para pruebas

Esta guía configura la VM Ubuntu local como servidor de prueba antes de migrar al VPS.

## Requisitos Mínimos

| Recurso | Mínimo (VM test) | Recomendado (VPS prod) |
|---|---|---|
| CPU | 2 vCPU | 4 vCPU |
| RAM | 4 GB | 8 GB |
| Disco | 40 GB | 100 GB SSD |
| OS | Ubuntu 22.04 LTS | Ubuntu 22.04 LTS |

## 1. Preparar Ubuntu

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl git docker.io docker-compose net-tools ufw
sudo systemctl enable docker && sudo systemctl start docker
sudo usermod -aG docker $USER
```

## 2. Conocer la IP de la VM

```bash
ip addr show
# Anotar la IP, ej: 192.168.1.105
# Esta IP va en los scripts como <IP_DEL_SERVIDOR>
```

Si la VM usa NAT en VirtualBox/VMware, cambiar a **Adaptador Puente (Bridged)**
para que sea accesible desde el host.

## 3. Instalar OpenVPN

Desde el directorio del repo, copiar los scripts al servidor:

```bash
# Desde Windows (PowerShell), copiar scripts a la VM:
scp vpn/scripts/*.sh usuario@192.168.1.105:/tmp/

# En la VM:
sudo bash /tmp/setup-server.sh 192.168.1.105
```

## 4. Generar primer equipo de prueba

```bash
# En la VM (como root):
sudo bash /tmp/gen-team-cert.sh team_01 192.168.1.105
# Genera: /etc/openvpn/clients/team_01.ovpn
```

Descargar el `.ovpn` al host Windows:

```powershell
scp usuario@192.168.1.105:/etc/openvpn/clients/team_01.ovpn .
```

## 5. Probar la conexión VPN

1. Instalar [OpenVPN Connect](https://openvpn.net/client/) en Windows
2. Importar `team_01.ovpn`
3. Conectar → deberías obtener IP `10.10.X.Y`

```powershell
# Verificar en Windows:
ipconfig | findstr "10.10"
# Debería mostrar la IP VPN asignada
```

## 6. Levantar servicios con Docker

```bash
# En la VM, desde el repo:
cd CTFHL4-INSANE/infra
cp .env.example .env
# Editar .env con los secrets

docker-compose up -d
```

## Variables de Entorno Necesarias

Crear `infra/.env`:

```env
MASTER_SECRET=cambia_esto_por_algo_aleatorio_largo
GRAFANA_PASSWORD=admin_password_seguro
```

Generar un secret seguro:
```bash
openssl rand -hex 32
```

## Verificar que Todo Funciona

```bash
# Ver estado de OpenVPN
sudo systemctl status openvpn@server

# Ver clientes conectados
sudo cat /var/log/openvpn/status.log

# Ver servicios Docker
docker-compose ps

# Ver logs de OpenVPN en Grafana
# Abrir en browser: http://127.0.0.1:3000 (desde la VM)
# o con SSH tunnel desde Windows:
# ssh -L 3000:127.0.0.1:3000 usuario@192.168.1.105
```

## Siguiente Paso

Con la VPN funcionando y al menos un equipo conectado, continuar con:
→ [Flag Service](flags-dinamicas.md)
