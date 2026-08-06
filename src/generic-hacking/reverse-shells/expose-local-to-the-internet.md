# Lokales ins Internet exponieren

{{#include ../../banners/hacktricks-training.md}}

**Das Ziel dieser Seite ist es, Alternativen vorzustellen, mit denen sich lokale rohe TCP-Ports und lokale Webanwendungen (HTTP) MINDESTENS ins Internet exponieren lassen, OHNE dass auf dem anderen Server etwas installiert werden muss (nur lokal, falls erforderlich).**

## **Serveo**

Unter [https://serveo.net/](https://serveo.net/) stehen mehrere Funktionen für http- und Port-Forwarding **kostenlos** zur Verfügung.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Unter [https://www.socketxp.com/download](https://www.socketxp.com/download) kannst du tcp und http ins Internet exponieren:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

Über [https://ngrok.com/](https://ngrok.com/) können http- und tcp-Ports nach außen freigegeben werden:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

Unter [https://telebit.cloud/](https://telebit.cloud/) können HTTP- und TCP-Ports freigegeben werden:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Über [https://localxpose.io/](https://localxpose.io/) sind mehrere HTTP- und Port-Forwarding-Funktionen **kostenlos** verfügbar.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

Unter [https://expose.dev/](https://expose.dev/) können http- und tcp-Ports exponiert werden:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

Von [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) aus lässt sich HTTP kostenlos ins Internet exponieren:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Cloudflares `cloudflared` CLI kann nicht authentifizierte „Quick“-Tunnel für schnelle Demos oder benannte Tunnel erstellen, die an die eigene Domain/Hostnames gebunden sind. Es unterstützt HTTP(S)-Reverse-Proxies sowie rohe TCP-Zuordnungen, die über Cloudflares Edge-Netzwerk geroutet werden.<sup>[[1]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
Benannte Tunnel ermöglichen es, mehrere Ingress-Regeln (HTTP, SSH, RDP usw.) innerhalb von `tunnel.yml` zu definieren, servicebezogene Zugriffsrichtlinien über Cloudflare Access zu unterstützen und für Persistenz als systemd-Container ausgeführt zu werden. Quick Tunnels sind anonym und kurzlebig – ideal für das Staging von phishing payloads oder webhook-Tests, aber Cloudflare garantiert keine Betriebszeit.<sup>[[1]](#references)</sup>

## Tailscale Funnel / Serve

Tailscale v1.52+ enthält die vereinheitlichten Workflows `tailscale serve` (Freigabe innerhalb des tailnet) und `tailscale funnel` (Veröffentlichung im öffentlichen Internet). Beide Befehle können HTTP(S) per Reverse Proxy weiterleiten oder rohes TCP mit automatischem TLS und kurzen `*.ts.net`-Hostnamen weiterleiten.<sup>[[3]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Verwende `--bg`, um die Konfiguration dauerhaft zu speichern, ohne einen Vordergrundprozess laufen zu lassen, und `tailscale funnel status`, um zu prüfen, welche Dienste aus dem öffentlichen Internet erreichbar sind. Da Funnel TLS auf dem lokalen Node beendet, bleiben alle Anmeldeaufforderungen, Header oder mTLS-Durchsetzungen unter deiner Kontrolle.

## Fast Reverse Proxy (frp)

`frp` ist eine self-hosted-Option, bei der du den Rendezvous-Server (`frps`) und den Client (`frpc`) kontrollierst. Es eignet sich hervorragend für red teams, die bereits einen VPS besitzen und deterministische Domains/Ports wünschen.

<details>
<summary>Beispielkonfiguration für frps/frpc</summary>
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

Neuere Releases bieten QUIC transport, token/OIDC-Authentifizierung, Bandbreitenlimits, Health Checks und auf Go-Templates basierende Range-Mappings – nützlich, um schnell mehrere Listener einzurichten, die auf Implants auf verschiedenen Hosts zurückverweisen.<sup>[[4]](#references)</sup>

## Pinggy (SSH-basiert)

Pinggy stellt über SSH zugängliche Tunnel über TCP/443 bereit und funktioniert daher auch hinter Captive Proxies, die nur HTTPS zulassen. Sessions dauern im kostenlosen Tarif 60 Minuten und können für schnelle Demos oder Webhook-Relays skriptiert werden.<sup>[[5]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
You can request custom domains and longer-lived tunnels on the paid tier, or recycle tunnels automatically by wrapping the command in a loop.

## Threat Intel- & OPSEC-Hinweise

Adversaries have increasingly abused ephemeral tunneling (especially Cloudflare's unauthenticated `trycloudflare.com` endpoints) to stage Remote Access Trojan payloads and hide C2 infrastructure. Proofpoint tracked campaigns since February 2024 that pushed AsyncRAT, Xworm, VenomRAT, GuLoader, and Remcos by pointing download stages to short-lived TryCloudflare URLs, making traditional static blocklists far less effective. Consider rotating tunnels and domains proactively, but also monitor for telltale external DNS lookups to the tunneler you are using so you can spot blue-team detection or infrastructure blocking attempts early.<sup>[[2]](#references)</sup>

## Referenzen

- [1] [Cloudflare Docs - Einen lokal verwalteten Tunnel erstellen](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [2] [Proofpoint - Threat Actor missbraucht Cloudflare Tunnels zur Bereitstellung von RATs](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
- [3] [Tailscale - Serve und Funnel werden wieder eingeführt](https://tailscale.com/blog/reintroducing-serve-funnel)
- [4] [fatedier/frp - Repository des Fast Reverse Proxy](https://github.com/fatedier/frp)
- [5] [Pinggy Documentation - Verwendung](https://pinggy.io/docs/usages/)

{{#include ../../banners/hacktricks-training.md}}
