# Exponer servicios locales a Internet

{{#include ../../banners/hacktricks-training.md}}

**El objetivo de esta página es proponer alternativas que permitan AL MENOS exponer puertos TCP locales sin procesar y webs locales (HTTP) a Internet SIN necesitar instalar nada en el otro servidor (solo en el local si es necesario).**

## **Serveo**

Desde [https://serveo.net/](https://serveo.net/), permite varias funcionalidades de HTTP y port forwarding **gratis**.
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

Desde [https://telebit.cloud/](https://telebit.cloud/) se puede exponer puertos http y tcp:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Desde [https://localxpose.io/](https://localxpose.io/), permite varias funciones de http y port forwarding **de forma gratuita**.
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

La CLI `cloudflared` de Cloudflare puede crear túneles "Quick" no autenticados para demos rápidas o túneles con nombre vinculados a tu propio dominio/hostnames. Soporta reverse proxies HTTP(S) así como mapeos TCP sin procesar enrutados a través del edge de Cloudflare.
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
Named tunnels te permiten definir múltiples reglas de ingress (HTTP, SSH, RDP, etc.) dentro de `tunnel.yml`, admitir políticas de acceso por servicio vía Cloudflare Access, y pueden ejecutarse como contenedores systemd para persistencia. Quick Tunnels son anónimos y efímeros — ideales para phishing payload staging o pruebas de webhooks, pero Cloudflare no garantiza el tiempo de actividad.

## Tailscale Funnel / Serve

Tailscale v1.52+ incluye los flujos de trabajo unificados `tailscale serve` (compartir dentro del tailnet) y `tailscale funnel` (publicar en Internet). Ambos comandos pueden hacer reverse proxy de HTTP(S) o reenviar TCP en bruto con TLS automático y nombres de host cortos `*.ts.net`.
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Usa `--bg` para persistir la configuración sin mantener un proceso en primer plano, y `tailscale funnel status` para auditar qué servicios son accesibles desde Internet pública. Debido a que Funnel termina TLS en el nodo local, cualquier solicitud de credenciales, encabezados o la aplicación de mTLS pueden permanecer bajo tu control.

## Fast Reverse Proxy (frp)

`frp` es una opción autoalojada donde controlas el servidor de rendezvous (`frps`) y el cliente (`frpc`). Es ideal para red teams que ya poseen un VPS y quieren dominios/puertos deterministas.

<details>
<summary>Configuración de ejemplo frps/frpc</summary>
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

Las versiones recientes añaden QUIC transport, token/OIDC auth, límites de ancho de banda, comprobaciones de salud y Go-template-based range mappings — útiles para desplegar rápidamente múltiples listeners que se mapean de vuelta a implants en diferentes hosts.

## Pinggy (basado en SSH)

Pinggy proporciona túneles accesibles por SSH sobre TCP/443, por lo que funciona incluso detrás de captive proxies que solo permiten HTTPS. Las sesiones duran 60 minutos en el nivel gratuito y pueden automatizarse para demos rápidas o webhook relays.
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
Puedes solicitar dominios personalizados y tunnels de mayor duración en el nivel de pago, o reciclar tunnels automáticamente envolviendo el comando en un bucle.

## Notas de inteligencia de amenazas y OPSEC

Los adversarios han abusado cada vez más de ephemeral tunneling (especialmente de los endpoints no autenticados de Cloudflare `trycloudflare.com`) para desplegar Remote Access Trojan payloads y ocultar infraestructura de C2. Proofpoint rastreó campañas desde febrero de 2024 que distribuyeron AsyncRAT, Xworm, VenomRAT, GuLoader y Remcos apuntando las etapas de descarga a URLs efímeras de TryCloudflare, lo que hace que las listas estáticas de bloqueo tradicionales sean mucho menos eficaces. Considera rotar tunnels y dominios de forma proactiva, pero también monitoriza las telltale external DNS lookups hacia el tunneler que estés usando para poder detectar pronto intentos de detección por parte del blue team o bloqueos de infraestructura.

## Referencias

- [Cloudflare Docs - Create a locally-managed tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [Proofpoint - Threat Actor Abuses Cloudflare Tunnels to Deliver RATs](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)

{{#include ../../banners/hacktricks-training.md}}
