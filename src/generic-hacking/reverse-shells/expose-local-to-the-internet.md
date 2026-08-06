# Exponer el entorno local a Internet

{{#include ../../banners/hacktricks-training.md}}

**El objetivo de esta página es proponer alternativas que permitan, COMO MÍNIMO, exponer puertos TCP sin procesar y webs locales (HTTP) a Internet SIN necesidad de instalar nada en el otro servidor (solo en el entorno local si fuera necesario).**

## **Serveo**

Desde [https://serveo.net/](https://serveo.net/), permite varias funcionalidades de HTTP y port forwarding **de forma gratuita**.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Desde [https://www.socketxp.com/download](https://www.socketxp.com/download), permite exponer tcp y http:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

Desde [https://ngrok.com/](https://ngrok.com/), permite exponer puertos http y tcp:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

Desde [https://telebit.cloud/](https://telebit.cloud/) permite exponer puertos http y tcp:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Desde [https://localxpose.io/](https://localxpose.io/), permite varias funciones de reenvío de HTTP y puertos **de forma gratuita**.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

Desde [https://expose.dev/](https://expose.dev/) permite exponer puertos http y tcp:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

Desde [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) permite exponer http de forma gratuita:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

La CLI `cloudflared` de Cloudflare puede crear túneles "Quick" no autenticados para demostraciones rápidas o túneles con nombre vinculados a tu propio dominio/hostnames. Admite proxies inversos HTTP(S), así como asignaciones TCP sin procesar enrutadas a través del edge de Cloudflare.<sup>[[1]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
Los túneles con nombre permiten definir múltiples reglas de ingress (HTTP, SSH, RDP, etc.) dentro de `tunnel.yml`, admiten políticas de acceso por servicio mediante Cloudflare Access y pueden ejecutarse como contenedores de systemd para ofrecer persistencia. Los Quick Tunnels son anónimos y efímeros: ideales para staging de payloads de phishing o pruebas de webhook, pero Cloudflare no garantiza su disponibilidad.<sup>[[1]](#references)</sup>

## Tailscale Funnel / Serve

Tailscale v1.52+ incluye los flujos de trabajo unificados `tailscale serve` (compartir dentro de la tailnet) y `tailscale funnel` (publicar en Internet). Ambos comandos pueden hacer reverse proxy de HTTP(S) o reenviar TCP sin procesar, con TLS automático y nombres de host cortos `*.ts.net`.<sup>[[3]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Usa `--bg` para persistir la configuración sin mantener un proceso en primer plano, y `tailscale funnel status` para auditar qué servicios son accesibles desde Internet público. Como Funnel termina TLS en el nodo local, cualquier solicitud de credenciales, header o enforcement de mTLS puede permanecer bajo tu control.

## Fast Reverse Proxy (frp)

`frp` es una opción self-hosted en la que controlas el servidor de rendezvous (`frps`) y el cliente (`frpc`). Es ideal para red teams que ya poseen un VPS y quieren dominios/puertos deterministas.

<details>
<summary>Configuración de ejemplo de frps/frpc</summary>
```bash
# Server: bind TCP/HTTP entry points and enable dashboard
./frps -c frps.toml

# Client: forward local 22 to remote port 6000 and a web app to vhost
./frpc -c <<'EOF'
serverAddr = "c2.example.com"
serverPort = 7000

[[proxies]]
name = "ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 6000

[[proxies]]
name = "panel"
type = "http"
localPort = 8080
customDomains = ["panel.example.com"]
EOF
```
</details>

Las versiones recientes añaden transporte QUIC, autenticación mediante token/OIDC, límites de bandwidth, health checks y asignaciones de rangos basadas en plantillas de Go, lo que resulta útil para poner en marcha rápidamente múltiples listeners que se conectan con implants en distintos hosts.<sup>[[4]](#references)</sup>

## Pinggy (basado en SSH)

Pinggy proporciona tunnels accesibles mediante SSH a través de TCP/443, por lo que funciona incluso detrás de proxies cautivos que solo permiten HTTPS. Las sesiones duran 60 minutos en el nivel gratuito y pueden automatizarse para demos rápidas o relays de webhook.<sup>[[5]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
Puedes solicitar dominios personalizados y túneles de mayor duración en el nivel de pago, o reciclar túneles automáticamente envolviendo el comando en un bucle.

## Inteligencia de amenazas y notas de OPSEC

Los adversarios han abusado cada vez más de los túneles efímeros (especialmente de los endpoints `trycloudflare.com` no autenticados de Cloudflare) para distribuir payloads de Remote Access Trojan y ocultar la infraestructura de C2. Proofpoint registró campañas desde febrero de 2024 que distribuyeron AsyncRAT, Xworm, VenomRAT, GuLoader y Remcos, apuntando las etapas de descarga a URLs de TryCloudflare de corta duración, lo que hace que las blocklists estáticas tradicionales sean mucho menos eficaces. Considera rotar los túneles y dominios de forma proactiva, pero también monitoriza las consultas DNS externas reveladoras al tunneler que estés utilizando para detectar pronto la detección por parte del blue-team o los intentos de bloquear la infraestructura.<sup>[[2]](#references)</sup>

## Referencias

- [1] [Cloudflare Docs - Crear un túnel gestionado localmente](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [2] [Proofpoint - Un actor de amenazas abusa de Cloudflare Tunnels para distribuir RATs](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
- [3] [Tailscale - Reintroducción de Serve y Funnel](https://tailscale.com/blog/reintroducing-serve-funnel)
- [4] [fatedier/frp - Repositorio de Fast Reverse Proxy](https://github.com/fatedier/frp)
- [5] [Documentación de Pinggy - Uso](https://pinggy.io/docs/usages/)

{{#include ../../banners/hacktricks-training.md}}
