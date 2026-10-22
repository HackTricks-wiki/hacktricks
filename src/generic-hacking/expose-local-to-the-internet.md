# Exponer un servicio local a Internet

{{#include ../banners/hacktricks-training.md}}

**El objetivo de esta página es proponer alternativas que permitan, como mínimo, exponer puertos TCP locales sin procesar y sitios web locales (HTTP) a Internet, SIN necesidad de instalar nada en el otro servidor (solo en el equipo local, si es necesario).**

## **Serveo**

La documentación de Serveo describe el reenvío SSH para endpoints HTTP y el reenvío TCP privado/público; para solicitar un puerto TCP público que no sea el 80/443 (incluido el puerto 0 para asignar uno aleatorio), es necesario tener un usuario registrado.<sup>[[1]](#references)</sup>

```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```

## SocketXP

La guía de inicio de SocketXP documenta `socketxp connect tcp://localhost:22` y `socketxp connect http://localhost:8080` para túneles TCP y HTTP; primero, el agente se autentica con un token del portal.<sup>[[2]](#references)</sup>

```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```

## Ngrok

La CLI de ngrok documenta túneles HTTP y TCP; sus preguntas frecuentes indican que los endpoints TCP del nivel gratuito requieren un método de pago válido y que no se realiza ningún cargo a la tarjeta.<sup>[[3]](#references)[[4]](#references)</sup>

```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```

## Telebit

La ayuda heredada de la CLI de Telebit.js documenta `telebit http <port>` para el reenvío HTTPS y `telebit tcp <local> [remote]` para TCP sin procesar; la disponibilidad depende de la implementación y del relay.<sup>[[5]](#references)</sup>

```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```

## LocalXpose

El sitio actual de LocalXpose documenta `loclx tunnel http --to 3000`, enumera compatibilidad con HTTP/TLS/TCP/UDP e indica que el plan gratuito cubre el uso personal y comercial ligero, mientras que los túneles TCP son una función de pago.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```

## Expose

Expose documenta `expose share` para URLs locales HTTP/HTTPS y un comando `expose share-port` exclusivo para PRO para puertos TCP.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```

## Localtunnel

El repositorio oficial de localtunnel describe cómo exponer localhost para realizar pruebas y documenta el siguiente comando NPX.<sup>[[10]](#references)</sup>

```bash
# Expose web in port 8000
npx localtunnel --port 8000
```

## Cloudflare Tunnel (cloudflared)

La documentación actual de Cloudflare muestra túneles «Quick» sin autenticación para desarrollo local, y la descripción general del producto incluye HTTP, HTTPS, TCP, SSH y RDP entre los protocolos publicados compatibles.<sup>[[11]](#references)[[12]](#references)</sup>

Para un túnel con nombre gestionado localmente, Cloudflare documenta el flujo de trabajo `tunnel login`, `create`, `route dns` y `--config ... run ...`.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```

Los túneles con nombre pueden definir varias reglas de ingreso en YAML; las políticas de Cloudflare Access pueden controlar el acceso a las aplicaciones publicadas, y Cloudflare documenta métodos de implementación con servicios y Docker para ejecutar conectores. Quick Tunnels son túneles de prueba anónimos y temporales, con un límite de 200 solicitudes concurrentes y sin compatibilidad con Server-Sent Events (SSE).<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

La CLI actual de Tailscale usa Serve para compartir solo dentro del tailnet y Funnel para compartir públicamente. Los comandos admiten destinos HTTP/HTTPS de reverse proxy y reenvío TCP; el modo TCP sin procesar de Funnel está limitado a los puertos 443, 8443 y 10000.<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```

Usa `--bg` para mantener la configuración sin dejar un proceso en primer plano, y usa `tailscale funnel status` para auditar qué servicios son accesibles desde la internet pública. Para los destinos de HTTPS Funnel, Tailscale documenta la terminación TLS en el nodo local antes de reenviar la solicitud al servicio local.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp` es una opción autohospedada en la que controlas el servidor de rendezvous (`frps`) y el cliente (`frpc`); su documentación describe cómo reenviar servicios locales detrás de NAT o de un firewall usando puertos o dominios remotos deterministas.<sup>[[20]](#references)</sup>

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

La documentación actual del proyecto incluye transporte QUIC, autenticación con token/OIDC, límites de ancho de banda, comprobaciones de estado y mapeos `range` de Go-template; consulta la versión correspondiente a tu implementación antes de usar cualquiera de esas opciones.<sup>[[20]](#references)</sup>

## Pinggy (basado en SSH)

Pinggy documenta el reenvío inverso de SSH por el puerto 443, por lo que puede funcionar en redes donde se bloquea el tráfico SSH saliente por el puerto 22. Su plan gratuito agota el tiempo de espera después de 60 minutos y usa una URL nueva al reconectarse, mientras que Pro añade túneles persistentes y dominios personalizados.<sup>[[21]](#references)[[22]](#references)</sup>

```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```

Puedes solicitar dominios personalizados y túneles persistentes en Pro.<sup>[[22]](#references)</sup> Puedes reciclar automáticamente los túneles temporales incluyendo el comando en un bucle.

## Notas de inteligencia sobre amenazas y OPSEC

Los adversarios han abusado de los túneles efímeros, incluidos los endpoints `trycloudflare.com` no autenticados de Cloudflare, para distribuir troyanos de acceso remoto mediante infraestructura temporal. Proofpoint informó de actividad observada por primera vez en febrero de 2024 que involucraba Xworm, AsyncRAT, VenomRAT, GuLoader y Remcos, y señaló que los túneles temporales complican las defensas que dependen de listas de bloqueo estáticas.<sup>[[23]](#references)</sup> Considera rotar los túneles y dominios de forma proactiva, y vigila las consultas DNS externas reveladoras al servicio de túneles que estés usando para detectar cuanto antes posibles intentos de detección del blue-team o de bloqueo de la infraestructura.

## References

- [1] [Documentación de Serveo](https://serveo.net/docs/)
- [2] [Documentación de SocketXP - Primeros pasos](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [Interfaz de línea de comandos del agente ngrok](https://ngrok.com/docs/agent/cli)
- [4] [Preguntas frecuentes de ngrok](https://ngrok.com/docs/faq)
- [5] [Ayuda de la CLI heredada de Telebit.js](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [Documentación de LocalXpose](https://localxpose.gitbook.io/docs)
- [8] [Expose - Compartir sitios](https://expose.dev/docs/client/sharing)
- [9] [Expose - Compartir puertos TCP](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [Repositorio de localtunnel/localtunnel](https://github.com/localtunnel/localtunnel)
- [11] [Documentación de Cloudflare - Configurar Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Descripción general de Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [13] [Documentación de Cloudflare - Comandos útiles de túnel](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Documentación de Cloudflare - Enrutamiento](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Documentación de Cloudflare - Archivo de configuración](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Políticas de Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Documentación de Cloudflare - Parámetros de ejecución](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Comando Serve de Tailscale](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Comando Funnel de Tailscale](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [Repositorio de fatedier/frp - Fast Reverse Proxy](https://github.com/fatedier/frp)
- [21] [Documentación de Pinggy - Uso](https://pinggy.io/docs/usages/)
- [22] [Pinggy - Túneles sencillos de localhost](https://pinggy.io/)
- [23] [Proofpoint - Un actor de amenazas abusa de Cloudflare Tunnels para distribuir RATs](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
{{#include ../banners/hacktricks-training.md}}
