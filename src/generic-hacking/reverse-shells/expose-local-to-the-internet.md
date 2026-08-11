# Lokales für das Internet verfügbar machen

{{#include ../../banners/hacktricks-training.md}}

**Das Ziel dieser Seite ist es, Alternativen vorzustellen, mit denen sich mindestens lokale rohe TCP-Ports und lokale Webseiten (HTTP) für das Internet verfügbar machen lassen, OHNE dass auf dem anderen Server etwas installiert werden muss (nur lokal, falls erforderlich).**

## **Serveo**

Die Dokumentation von Serveo beschreibt SSH-Forwarding für HTTP-Endpunkte sowie privates/öffentliches TCP-Forwarding; das Anfordern eines öffentlichen TCP-Ports, der nicht 80/443 entspricht (einschließlich Port 0 für einen zufälligen Port), erfordert einen registrierten Benutzer.<sup>[[1]](#references)</sup>
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Die Getting-Started-Anleitung von SocketXP dokumentiert `socketxp connect tcp://localhost:22` und `socketxp connect http://localhost:8080` für TCP- und HTTP-Tunnel; der Agent wird zunächst mit einem Portal-Token authentifiziert.<sup>[[2]](#references)</sup>
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

Die CLI-Dokumentation von ngrok beschreibt HTTP- und TCP-Tunnel; in der FAQ wird darauf hingewiesen, dass TCP-Endpunkte im kostenlosen Tarif eine gültige Zahlungsmethode erfordern und die Karte nicht belastet wird.<sup>[[3]](#references)[[4]](#references)</sup>
```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```
## Telebit

Die veraltete Telebit.js-CLI-Dokumentation beschreibt `telebit http <port>` für die HTTPS-Weiterleitung und `telebit tcp <local> [remote]` für unverändertes TCP; die Verfügbarkeit hängt vom Deployment und Relay ab.<sup>[[5]](#references)</sup>
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Die aktuelle Website von LocalXpose dokumentiert `loclx tunnel http --to 3000`, führt die Unterstützung für HTTP/TLS/TCP/UDP auf und besagt, dass der kostenlose Plan die private und leichte kommerzielle Nutzung abdeckt, während TCP tunneling eine Funktion kostenpflichtiger Pläne ist.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```
## Expose

Expose dokumentiert `expose share` für lokale HTTP/HTTPS-URLs und einen nur für PRO verfügbaren Befehl `expose share-port` für TCP-Ports.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```
## Localtunnel

Das offizielle Localtunnel-Repository beschreibt, wie localhost zum Testen freigegeben wird, und dokumentiert den folgenden NPX-Befehl.<sup>[[10]](#references)</sup>
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Cloudflares aktuelle Dokumentation zeigt nicht authentifizierte „Quick“-Tunnels für die lokale Entwicklung. Die Produktübersicht führt HTTP, HTTPS, TCP, SSH und RDP als unterstützte veröffentlichte Protokolle auf.<sup>[[11]](#references)[[12]](#references)</sup>

Für einen lokal verwalteten benannten Tunnel dokumentiert Cloudflare den Workflow mit `tunnel login`, `create`, `route dns` und `--config ... run ...`.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```
Named tunnels können mehrere Ingress-Regeln in YAML definieren; Cloudflare Access-Richtlinien können den Zugriff auf veröffentlichte Anwendungen steuern, und Cloudflare dokumentiert Service- und Docker-Bereitstellungspfade zum Ausführen von Connectors. Quick Tunnels sind anonyme, temporäre Tunnels zum Testen mit einem Limit von 200 gleichzeitigen Requests und ohne Unterstützung für Server-Sent Events (SSE).<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

Die aktuelle CLI von Tailscale verwendet Serve für das Teilen ausschließlich innerhalb des Tailnets und Funnel für das öffentliche Teilen. Die Befehle unterstützen HTTP/HTTPS-Reverse-Proxy-Ziele und TCP-Weiterleitung; der Raw-TCP-Modus von Funnel ist auf die Ports 443, 8443 und 10000 beschränkt.<sup>[[18]](#references)[[19]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Use `--bg`, um die Konfiguration dauerhaft zu speichern, ohne einen Vordergrundprozess aufrechtzuerhalten, und `tailscale funnel status`, um zu überprüfen, welche Services aus dem öffentlichen Internet erreichbar sind. Für HTTPS-Funnel-Ziele dokumentiert Tailscale die TLS-Terminierung auf dem lokalen Node, bevor die Anfrage an den lokalen Service weitergeleitet wird.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp` ist eine self-hosted Option, bei der du den Rendezvous-Server (`frps`) und den Client (`frpc`) kontrollierst. Die Dokumentation behandelt die Weiterleitung lokaler Services hinter NAT oder einer Firewall mit deterministischen Remote-Ports/Domains.<sup>[[20]](#references)</sup>

<details>
<summary>Beispielkonfiguration für frps/frpc</summary>
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

Die aktuelle Projektdokumentation umfasst QUIC-Transport, Token/OIDC-Authentifizierung, Bandbreitenbegrenzungen, Health Checks und Go-Template-Range-Mappings. Konsultiere die zum Deployment passende Version, bevor du eine dieser Optionen verwendest.<sup>[[20]](#references)</sup>

## Pinggy (SSH-based)

Pinggy dokumentiert SSH-Reverse-Forwarding über Port 443, sodass es in Netzwerken funktionieren kann, in denen ausgehendes SSH über Port 22 blockiert ist. Der kostenlose Tarif läuft nach 60 Minuten ab und verwendet nach dem erneuten Verbinden eine neue URL, während Pro persistente Tunnel und benutzerdefinierte Domains hinzufügt.<sup>[[21]](#references)[[22]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```
Du kannst auf Pro benutzerdefinierte Domains und persistente Tunnels anfordern.<sup>[[22]](#references)</sup> Temporäre Tunnels lassen sich automatisch wiederverwenden, indem du den Befehl in eine Schleife einbindest.

## Threat intel & OPSEC-Hinweise

Adversaries haben ephemeral tunneling missbraucht, darunter nicht authentifizierte `trycloudflare.com`-Endpoints von Cloudflare, um Remote Access Trojans über temporäre Infrastruktur zu verbreiten. Proofpoint berichtete über erstmals im Februar 2024 beobachtete Aktivitäten mit Xworm, AsyncRAT, VenomRAT, GuLoader und Remcos und stellte fest, dass temporäre Tunnels die Abwehrmaßnahmen erschweren, die auf statischen Blocklists basieren.<sup>[[23]](#references)</sup> Erwäge, Tunnels und Domains proaktiv zu rotieren, und überwache externe DNS-Abfragen an den von dir verwendeten Tunneler, damit du die Erkennung durch das blue team oder Versuche zur Blockierung der Infrastruktur frühzeitig bemerkst.

## References

- [1] [Serveo-Dokumentation](https://serveo.net/docs/)
- [2] [SocketXP-Dokumentation - Erste Schritte](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [ngrok Agent Command Line Interface](https://ngrok.com/docs/agent/cli)
- [4] [ngrok FAQ](https://ngrok.com/docs/faq)
- [5] [Telebit.js – Hilfe zur Legacy-CLI](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [LocalXpose-Dokumentation](https://localxpose.gitbook.io/docs)
- [8] [Expose - Websites teilen](https://expose.dev/docs/client/sharing)
- [9] [Expose - TCP-Ports teilen](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [Repository localtunnel/localtunnel](https://github.com/localtunnel/localtunnel)
- [11] [Cloudflare-Dokumentation - Cloudflare Tunnel einrichten](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Übersicht über Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [13] [Cloudflare-Dokumentation - Nützliche Tunnel-Befehle](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Cloudflare-Dokumentation - Routing](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Cloudflare-Dokumentation - Konfigurationsdatei](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Cloudflare-Access-Richtlinien](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Cloudflare-Dokumentation - Run-Parameter](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Tailscale-Serve-Befehl](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Tailscale-Funnel-Befehl](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [Repository fatedier/frp - Fast Reverse Proxy](https://github.com/fatedier/frp)
- [21] [Pinggy-Dokumentation - Verwendung](https://pinggy.io/docs/usages/)
- [22] [Pinggy - Einfache Localhost-Tunnels](https://pinggy.io/)
- [23] [Proofpoint - Threat Actor missbraucht Cloudflare Tunnels zur Verbreitung von RATs](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
{{#include ../../banners/hacktricks-training.md}}
