# Exponer recursos locales a Internet

**El objetivo de esta página es proponer alternativas que permitan, COMO MÍNIMO, exponer puertos TCP sin procesar y webs locales (HTTP) a Internet SIN necesidad de instalar nada en el otro servidor (solo en el equipo local si es necesario).**

## **Serveo**

La documentación de Serveo describe el forwarding mediante SSH para endpoints HTTP y el forwarding TCP privado/público; solicitar un puerto TCP público distinto de 80/443 (incluido el puerto 0 para obtener un puerto aleatorio) requiere un usuario registrado.<sup>[[1]](#references)</sup>
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

La guía de inicio de SocketXP documenta `socketxp connect tcp://localhost:22` y `socketxp connect http://localhost:8080` para túneles TCP y HTTP; el agente se autentica primero con un token del portal.<sup>[[2]](#references)</sup>
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

La CLI de ngrok documenta túneles HTTP y TCP; sus FAQ indican que los endpoints TCP del nivel gratuito requieren un método de pago válido y que no se realiza ningún cargo a la tarjeta.<sup>[[3]](#references)[[4]](#references)</sup>
```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```
## Telebit

La ayuda del CLI heredado de Telebit.js documenta `telebit http <port>` para el reenvío HTTPS y `telebit tcp <local> [remote]` para TCP sin procesar; la disponibilidad depende del despliegue y del relay.<sup>[[5]](#references)</sup>
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

El sitio actual de LocalXpose documenta `loclx tunnel http --to 3000`, indica compatibilidad con HTTP/TLS/TCP/UDP y señala que el plan gratuito cubre el uso personal y comercial ligero, mientras que el tunneling TCP es una capacidad de los planes de pago.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```
## Expose

Expose documenta `expose share` para URLs locales HTTP/HTTPS y un comando `expose share-port` exclusivo de PRO para puertos TCP.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```
## Localtunnel

El repositorio oficial de localtunnel describe cómo exponer localhost para realizar pruebas y documenta el siguiente comando de NPX.<sup>[[10]](#references)</sup>
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

La documentación actual de Cloudflare muestra túneles "Quick" no autenticados para desarrollo local, y la descripción general del producto incluye HTTP, HTTPS, TCP, SSH y RDP entre los protocolos publicados compatibles.<sup>[[11]](#references)[[12]](#references)</sup>

Para un named tunnel administrado localmente, Cloudflare documenta el flujo de trabajo `tunnel login`, `create`, `route dns` y `--config ... run ...`.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```
Los named tunnels pueden definir múltiples reglas de ingress en YAML; las políticas de Cloudflare Access pueden controlar el acceso a las aplicaciones publicadas, y Cloudflare documenta las rutas de deployment de servicios y Docker para ejecutar connectors. Los Quick Tunnels son tunnels de testing anónimos y temporales, con un límite de 200 solicitudes simultáneas y sin compatibilidad con Server-Sent Events (SSE).<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

La CLI actual de Tailscale usa Serve para compartir solo dentro del tailnet y Funnel para compartir públicamente. Los comandos admiten targets de reverse-proxy HTTP/HTTPS y forwarding TCP; el modo TCP sin formato de Funnel está limitado a los puertos 443, 8443 y 10000.<sup>[[18]](#references)[[19]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Usa `--bg` para conservar la configuración sin mantener un proceso en primer plano, y usa `tailscale funnel status` para auditar qué servicios son accesibles desde Internet público. Para los destinos HTTPS Funnel, Tailscale documenta la terminación TLS en el nodo local antes de reenviar la solicitud al servicio local.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp` es una opción self-hosted en la que controlas el servidor de rendezvous (`frps`) y el cliente (`frpc`); su documentación cubre el reenvío de servicios locales detrás de NAT o un firewall con puertos/dominios remotos deterministas.<sup>[[20]](#references)</sup>

<details>
<summary>Configuración de ejemplo de frps/frpc</summary>
```bash
# Server: start frps with its server configuration
./frps -c frps.toml

# Client: save this as frpc.toml, then start it
cat > frpc.toml <<'EOF'
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
./frpc -c frpc.toml
```
</details>

La documentación actual del proyecto incluye transporte QUIC, autenticación mediante token/OIDC, límites de ancho de banda, comprobaciones de estado y asignaciones de range de Go-template; consulta la release correspondiente a tu despliegue antes de usar cualquiera de esas opciones.<sup>[[20]](#references)</sup>

## Pinggy (basado en SSH)

Pinggy documenta el reenvío inverso SSH a través del puerto 443, por lo que puede funcionar en redes donde el SSH saliente por el puerto 22 está bloqueado. Su plan gratuito se agota después de 60 minutos y utiliza una URL nueva tras volver a conectarse, mientras que Pro añade túneles persistentes y dominios personalizados.<sup>[[21]](#references)[[22]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```
Puedes solicitar dominios personalizados y túneles persistentes en Pro.<sup>[[22]](#references)</sup> Puedes reciclar túneles temporales automáticamente envolviendo el comando en un bucle.

## Threat intel & OPSEC notes

Los adversarios han abusado de los túneles efímeros, incluidos los endpoints no autenticados `trycloudflare.com` de Cloudflare, para distribuir Remote Access Trojans mediante infraestructura temporal. Proofpoint informó sobre actividad observada por primera vez en febrero de 2024 relacionada con Xworm, AsyncRAT, VenomRAT, GuLoader y Remcos, y señaló que los túneles temporales complican las defensas que dependen de blocklists estáticas.<sup>[[23]](#references)</sup> Considera rotar los túneles y dominios de forma proactiva, y monitoriza las consultas DNS externas reveladoras al tunneler que estés utilizando para detectar rápidamente la identificación por parte del blue team o los intentos de bloquear la infraestructura.

## References

- [1] [Documentación de Serveo](https://serveo.net/docs/)
- [2] [Documentación de SocketXP - Primeros pasos](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [Interfaz de línea de comandos del agente de ngrok](https://ngrok.com/docs/agent/cli)
- [4] [Preguntas frecuentes de ngrok](https://ngrok.com/docs/faq)
- [5] [Ayuda del CLI heredado de Telebit.js](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [Documentación de LocalXpose](https://localxpose.gitbook.io/docs)
- [8] [Expose - Compartir sitios](https://expose.dev/docs/client/sharing)
- [9] [Expose - Compartir puertos TCP](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [repositorio de localtunnel/localtunnel](https://github.com/localtunnel/localtunnel)
- [11] [Cloudflare Docs - Configurar Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Descripción general de Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [13] [Cloudflare Docs - Comandos útiles de tunnel](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Cloudflare Docs - Routing](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Cloudflare Docs - Archivo de configuración](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Políticas de Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Cloudflare Docs - Parámetros de ejecución](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Comando Serve de Tailscale](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Comando Funnel de Tailscale](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [repositorio de fatedier/frp - Fast Reverse Proxy](https://github.com/fatedier/frp)
- [21] [Documentación de Pinggy - Uso](https://pinggy.io/docs/usages/)
- [22] [Pinggy - Túneles simples para localhost](https://pinggy.io/)
- [23] [Proofpoint - Threat Actor Abuses Cloudflare Tunnels to Deliver RATs](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
{{#include ../../banners/hacktricks-training.md}}
