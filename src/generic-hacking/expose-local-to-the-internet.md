# Lokales im Internet verfügbar machen

{{#include ../banners/hacktricks-training.md}}

**Ziel dieser Seite ist es, Alternativen vorzustellen, mit denen sich mindestens lokale Raw-TCP-Ports und lokale Websites (HTTP) im Internet verfügbar machen lassen, OHNE etwas auf dem anderen Server installieren zu müssen (nur lokal, falls erforderlich).**

## **Serveo**

Die Dokumentation von Serveo beschreibt SSH-Weiterleitungen für HTTP-Endpunkte sowie private/öffentliche TCP-Weiterleitungen. Für einen öffentlichen TCP-Port außerhalb von 80/443 (einschließlich Port 0 für einen zufälligen Port) ist ein registrierter Benutzer erforderlich.<sup>[[1]](#references)</sup>

```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```

## SocketXP

Die Einstiegsanleitung von SocketXP beschreibt `socketxp connect tcp://localhost:22` und `socketxp connect http://localhost:8080` für TCP- und HTTP-Tunnel; zuvor wird der Agent mit einem Portal-Token authentifiziert.<sup>[[2]](#references)</sup>

```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```

## Ngrok

Die CLI von ngrok dokumentiert HTTP- und TCP-Tunnel; laut FAQ ist für TCP-Endpunkte im kostenlosen Tarif eine gültige Zahlungsmethode erforderlich, die Karte wird jedoch nicht belastet.<sup>[[3]](#references)[[4]](#references)</sup>

```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```

## Telebit

Die ältere Telebit.js-CLI-Hilfe dokumentiert `telebit http <port>` für die HTTPS-Weiterleitung und `telebit tcp <local> [remote]` für rohe TCP-Verbindungen; die Verfügbarkeit hängt von der Bereitstellung und dem Relay ab.<sup>[[5]](#references)</sup>

```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```

## LocalXpose

Auf der aktuellen Website von LocalXpose ist `loclx tunnel http --to 3000` dokumentiert. Außerdem werden HTTP, TLS, TCP und UDP unterstützt. Laut Website deckt der kostenlose Tarif die private und leichte kommerzielle Nutzung ab, während TCP-Tunneling nur mit einem kostenpflichtigen Tarif verfügbar ist.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```

## Expose

Expose dokumentiert `expose share` für lokale HTTP/HTTPS-URLs und einen nur in PRO verfügbaren Befehl `expose share-port` für TCP-Ports.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```

## Localtunnel

Das offizielle Localtunnel-Repository beschreibt, wie localhost für Tests freigegeben wird, und dokumentiert den folgenden NPX-Befehl.<sup>[[10]](#references)</sup>

```bash
# Expose web in port 8000
npx localtunnel --port 8000
```

## Cloudflare Tunnel (cloudflared)

Cloudflares aktuelle Dokumentation beschreibt nicht authentifizierte „Quick“-Tunnel für die lokale Entwicklung. In der Produktübersicht werden HTTP, HTTPS, TCP, SSH und RDP als unterstützte veröffentlichte Protokolle aufgeführt.<sup>[[11]](#references)[[12]](#references)</sup>

Für einen lokal verwalteten benannten Tunnel dokumentiert Cloudflare den Workflow `tunnel login`, `create`, `route dns` und `--config ... run ...`.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```

Named Tunnels können mehrere ingress rules in YAML definieren; Cloudflare Access-Richtlinien können den Zugriff auf veröffentlichte Anwendungen steuern, und Cloudflare dokumentiert Service- und Docker-Bereitstellungswege zum Ausführen von Connectors. Quick Tunnels sind anonyme, temporäre Test-Tunnels mit einem Limit von 200 gleichzeitigen Anfragen und ohne Unterstützung für Server-Sent Events (SSE).<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

Die aktuelle CLI von Tailscale verwendet Serve für das Teilen innerhalb des Tailnets und Funnel für öffentliches Teilen. Die Befehle unterstützen HTTP/HTTPS-Reverse-Proxy-Ziele und TCP-Weiterleitung; der Raw-TCP-Modus von Funnel ist auf die Ports 443, 8443 und 10000 beschränkt.<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```

Verwende `--bg`, um die Konfiguration dauerhaft zu speichern, ohne einen Prozess im Vordergrund laufen zu lassen, und verwende `tailscale funnel status`, um zu prüfen, welche Dienste aus dem öffentlichen Internet erreichbar sind. Bei HTTPS-Funnel-Zielen wird laut Tailscale TLS auf dem lokalen Knoten beendet, bevor die Anfrage an den lokalen Dienst weitergeleitet wird.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp` ist eine selbst gehostete Option, bei der du den Rendezvous-Server (`frps`) und den Client (`frpc`) kontrollierst. Die Dokumentation beschreibt, wie lokale Dienste hinter NAT oder einer Firewall über festgelegte Remote-Ports oder -Domains weitergeleitet werden.<sup>[[20]](#references)</sup>

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

Die aktuelle Projektdokumentation umfasst QUIC-Transport, Token-/OIDC-Authentifizierung, Bandbreitenlimits, Health Checks und Go-Template-Range-Mappings – konsultieren Sie vor der Verwendung dieser Optionen die zu Ihrer Bereitstellung passende Release-Version.<sup>[[20]](#references)</sup>

## Pinggy (SSH-basiert)

Pinggy dokumentiert SSH-Reverse-Forwarding über Port 443, sodass es in Netzwerken funktionieren kann, in denen ausgehendes SSH über Port 22 blockiert ist. Der kostenlose Tarif läuft nach 60 Minuten ab und verwendet nach einer erneuten Verbindung eine neue URL, während Pro persistente Tunnels und benutzerdefinierte Domains bietet.<sup>[[21]](#references)[[22]](#references)</sup>

```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```

Auf Pro können Sie benutzerdefinierte Domains und persistente Tunnels anfordern.<sup>[[22]](#references)</sup> Sie können temporäre Tunnels automatisch wiederverwenden, indem Sie den Befehl in eine Schleife einbinden.

## Hinweise zu Threat Intelligence und OPSEC

Angreifer haben kurzlebige Tunneling-Dienste missbraucht, darunter die nicht authentifizierten `trycloudflare.com`-Endpunkte von Cloudflare, um über temporäre Infrastruktur Remote Access Trojans auszuliefern. Proofpoint berichtete über Aktivitäten, die erstmals im Februar 2024 beobachtet wurden und Xworm, AsyncRAT, VenomRAT, GuLoader und Remcos betrafen. Außerdem wies Proofpoint darauf hin, dass temporäre Tunnels Abwehrmaßnahmen erschweren, die auf statischen Blocklisten beruhen.<sup>[[23]](#references)</sup> Erwägen Sie, Tunnels und Domains proaktiv zu wechseln, und überwachen Sie verräterische externe DNS-Abfragen an den von Ihnen verwendeten Tunneling-Dienst, damit Sie frühzeitig blue-team-Erkennung oder Versuche, die Infrastruktur zu blockieren, erkennen können.

## References

- [1] [Serveo-Dokumentation](https://serveo.net/docs/)
- [2] [SocketXP-Dokumentation – Erste Schritte](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [ngrok-Agent-Befehlszeilenschnittstelle](https://ngrok.com/docs/agent/cli)
- [4] [ngrok-FAQ](https://ngrok.com/docs/faq)
- [5] [Hilfe zur veralteten Telebit.js-CLI](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [LocalXpose-Dokumentation](https://localxpose.gitbook.io/docs)
- [8] [Expose – Websites teilen](https://expose.dev/docs/client/sharing)
- [9] [Expose – TCP-Ports teilen](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [Repository localtunnel/localtunnel](https://github.com/localtunnel/localtunnel)
- [11] [Cloudflare-Dokumentation – Cloudflare Tunnel einrichten](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Übersicht über Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [13] [Cloudflare-Dokumentation – Nützliche Tunnel-Befehle](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Cloudflare-Dokumentation – Routing](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Cloudflare-Dokumentation – Konfigurationsdatei](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Cloudflare-Access-Richtlinien](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Cloudflare-Dokumentation – Run-Parameter](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Tailscale-Serve-Befehl](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Tailscale-Funnel-Befehl](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [fatedier/frp – Fast Reverse Proxy-Repository](https://github.com/fatedier/frp)
- [21] [Pinggy-Dokumentation – Verwendung](https://pinggy.io/docs/usages/)
- [22] [Pinggy – Einfache Localhost-Tunnels](https://pinggy.io/)
- [23] [Proofpoint – Bedrohungsakteur missbraucht Cloudflare Tunnels, um RATs auszuliefern](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
{{#include ../banners/hacktricks-training.md}}
