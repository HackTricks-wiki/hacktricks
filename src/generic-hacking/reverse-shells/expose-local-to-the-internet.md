# Lokal ins Internet freigeben

{{#include ../../banners/hacktricks-training.md}}

**Das Ziel dieser Seite ist es, Alternativen vorzuschlagen, die MINDESTENS erlauben, lokale rohe TCP-Ports und lokale Webs (HTTP) dem Internet zugänglich zu machen, OHNE etwas auf dem anderen Server installieren zu müssen (nur lokal, falls nötig).**

## **Serveo**

Über [https://serveo.net/](https://serveo.net/) bietet es mehrere http- und Port-Forwarding-Funktionen **kostenlos**.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Über [https://www.socketxp.com/download](https://www.socketxp.com/download) lässt sich tcp und http freigeben:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

Laut [https://ngrok.com/](https://ngrok.com/) ermöglicht es, http- und tcp-Ports freizugeben:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

Über [https://telebit.cloud/](https://telebit.cloud/) können http- und tcp-Ports freigegeben werden:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Von [https://localxpose.io/](https://localxpose.io/) ermöglicht es mehrere http- und port forwarding-Funktionen **kostenlos**.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

Von [https://expose.dev/](https://expose.dev/) aus ermöglicht es, http- und tcp-Ports zugänglich zu machen:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

Von [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) ermöglicht es, http kostenlos zugänglich zu machen:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Cloudflare's `cloudflared` CLI kann nicht authentifizierte "Quick" tunnels für schnelle Demos erstellen oder named tunnels, die an Ihre eigenen domain/hostnames gebunden sind. Es unterstützt HTTP(S) reverse proxies sowie raw TCP mappings, die über Cloudflare's edge geroutet werden.
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
Named tunnels ermöglichen es, mehrere Ingress-Regeln (HTTP, SSH, RDP usw.) in `tunnel.yml` zu definieren, unterstützen pro Dienst Zugriffspolicys über Cloudflare Access und können als systemd-Container für Persistenz laufen. Quick Tunnels sind anonym und flüchtig — ideal zum Staging von Phishing-Payloads oder für Webhook-Tests, aber Cloudflare garantiert keine Verfügbarkeit.

## Tailscale Funnel / Serve

Tailscale v1.52+ liefert die vereinheitlichten Workflows `tailscale serve` (Freigabe innerhalb des tailnet) und `tailscale funnel` (Veröffentlichung im öffentlichen Internet). Beide Befehle können als Reverse-Proxy für HTTP(S) fungieren oder rohen TCP-Verkehr weiterleiten, mit automatischem TLS und kurzen `*.ts.net` Hostnamen.
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Nutzen Sie `--bg`, um die Konfiguration persistent zu speichern, ohne einen Vordergrundprozess offen zu halten, und `tailscale funnel status`, um zu prüfen, welche Dienste aus dem öffentlichen Internet erreichbar sind. Da Funnel TLS auf dem lokalen Node terminiert, können alle credential prompts, headers oder mTLS enforcement unter Ihrer Kontrolle bleiben.

## Fast Reverse Proxy (frp)

`frp` ist eine selbst gehostete Option, bei der Sie den Rendezvous-Server (`frps`) und den Client (`frpc`) kontrollieren. Es eignet sich hervorragend für red teams, die bereits eine VPS besitzen und deterministische domains/ports wollen.

<details>
<summary>Beispiel frps/frpc-Konfiguration</summary>
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

Neuere Releases fügen QUIC transport, token/OIDC auth, bandwidth caps, health checks und Go-template-based range mappings hinzu — nützlich, um schnell mehrere listeners bereitzustellen, die auf implants auf verschiedenen hosts zurückverweisen.

## Pinggy (SSH-based)

Pinggy stellt SSH-accessible tunnels über TCP/443 bereit, sodass es auch hinter captive proxies funktioniert, die nur HTTPS erlauben. Sitzungen dauern im free tier 60 Minuten und lassen sich per Skript für schnelle Demos oder webhook relays verwenden.
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
Sie können benutzerdefinierte Domains und längerlebige Tunnels im kostenpflichtigen Tarif anfordern, oder Tunnels automatisch recyceln, indem Sie den Befehl in einer Schleife ausführen.

## Hinweise zu Threat-Intel & OPSEC

Angreifer haben zunehmend ephemeral tunneling (insbesondere Cloudflare's unauthenticated `trycloudflare.com` endpoints) missbraucht, um Remote Access Trojan payloads zu platzieren und C2-Infrastruktur zu verbergen. Proofpoint verfolgte seit Februar 2024 Kampagnen, die AsyncRAT, Xworm, VenomRAT, GuLoader und Remcos ausspielten, indem sie Download-Stages auf kurzlebige TryCloudflare-URLs verweisten, wodurch traditionelle statische Blocklisten deutlich weniger wirksam wurden. Erwägen Sie, Tunnels und Domains proaktiv zu rotieren, überwachen Sie aber auch auffällige externe DNS-Abfragen an den von Ihnen genutzten tunneler, damit Sie blue-team detection oder infrastructure blocking attempts frühzeitig erkennen können.

## References

- [Cloudflare Docs - Create a locally-managed tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [Proofpoint - Threat Actor Abuses Cloudflare Tunnels to Deliver RATs](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)

{{#include ../../banners/hacktricks-training.md}}
