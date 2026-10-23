# Lokales für das Internet freigeben

{{#include ../banners/hacktricks-training.md}}

**Ziel dieser Seite ist es, Alternativen vorzustellen, mit denen mindestens lokale Raw-TCP-Ports und lokale Websites (HTTP) im Internet erreichbar gemacht werden können, OHNE etwas auf dem anderen Server installieren zu müssen (nur lokal, falls nötig).**

Informationen zum Weiterleiten zwischen Hosts, statt einen Dienst über ein öffentliches Relay bereitzustellen, findest du unter [Tunneling and Port Forwarding](tunneling-and-port-forwarding.md).

## **Serveo**

Die Dokumentation von Serveo beschreibt SSH-Forwarding für HTTP-Endpunkte sowie privates und öffentliches TCP-Forwarding. Port `0` fordert auch für anonyme Sitzungen einen zufälligen öffentlichen TCP-Port an. Diese Sitzungen sind jedoch zeitlich und hinsichtlich der Verbindungen begrenzt. Für die Anforderung eines bestimmten öffentlichen TCP-Ports ist ein kostenpflichtiges Konto erforderlich.<sup>[[1]](#references)</sup>

```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```

## SocketXP

Die Getting-started-Anleitung von SocketXP dokumentiert `socketxp connect tcp://localhost:22` und `socketxp connect http://localhost:8080` für TCP- und HTTP-Tunnel; der Agent wird zuvor mit einem Portal-Token authentifiziert.<sup>[[2]](#references)</sup>

```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```

## Ngrok

Die CLI von ngrok dokumentiert HTTP- und TCP-Tunnel. TCP-Endpunkte erfordern eine reservierte TCP-Adresse im Konto; beim kostenlosen Tarif ist außerdem eine gültige Zahlungsmethode erforderlich, die laut FAQ nicht belastet wird.<sup>[[3]](#references)[[4]](#references)</sup>

```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```

## Telebit

Die Hilfe der älteren Telebit.js-CLI dokumentiert `telebit http <port>` für die HTTPS-Weiterleitung und `telebit tcp <local> [remote]` für rohes TCP; die Verfügbarkeit hängt von der Bereitstellung und dem Relay ab.<sup>[[5]](#references)</sup>

```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```

## LocalXpose

Die aktuelle Website von LocalXpose dokumentiert `loclx tunnel http --to 3000`, listet die Unterstützung für HTTP/TLS/TCP/UDP auf und gibt an, dass der kostenlose Tarif die private und leichte kommerzielle Nutzung abdeckt, während TCP-Tunneling eine kostenpflichtige Tarifoption ist.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```

## Freigeben

Expose dokumentiert `expose share` für lokale HTTP/HTTPS-URLs und einen nur PRO-Nutzern verfügbaren Befehl `expose share-port` für TCP-Ports.<sup>[[8]](#references)[[9]](#references)</sup>

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

Die aktuellen Dokumente von Cloudflare beschreiben nicht authentifizierte „Quick“-Tunnels für die lokale Entwicklung. In der Produktübersicht werden HTTP, HTTPS, TCP, SSH und RDP als unterstützte veröffentlichte Protokolle aufgeführt.<sup>[[11]](#references)[[12]](#references)</sup> Im Gegensatz zu HTTP(S) sind veröffentlichte TCP-, SSH- und RDP-Routen mit einem Standardclient nicht direkt erreichbar: Cloudflare benötigt `cloudflared` auf dem verbindenden Client. Daher erfüllen diese Routen nicht die Anforderung dieser Seite, für Raw TCP keine Client-Installation zu benötigen.<sup>[[24]](#references)</sup>

Für einen lokal verwalteten Named Tunnel dokumentiert Cloudflare den Workflow `tunnel login`, `create`, `route dns` und `--config ... run ...`.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```

Benannte Tunnels können mehrere ingress-Regeln in YAML definieren; Cloudflare Access-Richtlinien können den Zugriff auf veröffentlichte Anwendungen steuern, und Cloudflare dokumentiert Service- und Docker-Deployment-Pfade zum Ausführen von Connectors. Quick Tunnels sind anonyme, temporäre Test-Tunnels mit einem Limit von 200 gleichzeitigen Anfragen und ohne Unterstützung für Server-Sent Events (SSE).<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

Tailscales aktuelle CLI verwendet Serve für das Teilen nur im tailnet und Funnel für das öffentliche Teilen. Die Befehle unterstützen HTTP/HTTPS-Reverse-Proxy-Ziele und TCP-Weiterleitung; Funnels Raw-TCP-Modus ist auf die Ports 443, 8443 und 10000 beschränkt.<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```

Verwende `--bg`, um die Konfiguration dauerhaft zu speichern, ohne einen Prozess im Vordergrund laufen zu lassen, und prüfe mit `tailscale funnel status`, welche Dienste aus dem öffentlichen Internet erreichbar sind. Für HTTPS-Funnel-Ziele dokumentiert Tailscale, dass TLS auf dem lokalen Knoten terminiert wird, bevor die Anfrage an den lokalen Dienst weitergeleitet wird.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp` ist eine selbst gehostete Option, bei der du den Rendezvous-Server (`frps`) und den Client (`frpc`) kontrollierst. Die Dokumentation beschreibt, wie lokale Dienste hinter NAT oder einer Firewall mit festgelegten Remote-Ports oder Domains weitergeleitet werden.<sup>[[20]](#references)</sup>

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

Die aktuelle Projektdokumentation umfasst QUIC-Transport, Token-/OIDC-Authentifizierung, Bandbreitenlimits, Health Checks und Go-Template-Range-Mappings. Konsultiere die Version, die zu deinem Deployment passt, bevor du eine dieser Optionen verwendest.<sup>[[20]](#references)</sup>

## Pinggy (SSH-basiert)

Pinggy dokumentiert SSH-Reverse-Forwarding über Port 443. Daher kann es in Netzwerken funktionieren, in denen ausgehendes SSH über Port 22 blockiert ist. Beim kostenlosen Tarif läuft die Verbindung nach 60 Minuten ab und verwendet nach der erneuten Verbindung eine neue URL. Pro bietet persistente Tunnels und benutzerdefinierte Domains.<sup>[[21]](#references)[[22]](#references)</sup>

```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```

Sie können unter Pro.<sup>[[22]](#references)</sup> benutzerdefinierte Domains und persistente Tunnel anfordern. Temporäre Tunnel lassen sich automatisch wiederverwenden, indem Sie den Befehl in eine Schleife einbetten.

## Threat Intel- und OPSEC-Hinweise

Angreifer haben kurzlebige Tunneling-Dienste missbraucht, darunter Cloudflares nicht authentifizierte `trycloudflare.com`-Endpunkte, um über temporäre Infrastruktur Remote Access Trojans auszuliefern. Proofpoint berichtete über Aktivitäten, die erstmals im Februar 2024 beobachtet wurden und Xworm, AsyncRAT, VenomRAT, GuLoader und Remcos umfassten. Außerdem wurde darauf hingewiesen, dass temporäre Tunnel Abwehrmaßnahmen erschweren, die auf statischen Blocklisten beruhen.<sup>[[23]](#references)</sup> Erwägen Sie, Tunnel und Domains proaktiv zu wechseln, und überwachen Sie verräterische externe DNS-Abfragen an den von Ihnen verwendeten Tunneling-Dienst. So können Sie frühzeitig Blue-Team-Erkennungsversuche oder Versuche, Ihre Infrastruktur zu blockieren, bemerken.

## References

- [1] [Serveo-Dokumentation](https://serveo.net/docs/)
- [2] [SocketXP-Dokumentation – Erste Schritte](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [ngrok Agent-Befehlszeilenschnittstelle](https://ngrok.com/docs/agent/cli)
- [4] [ngrok-FAQ](https://ngrok.com/docs/faq)
- [5] [Hilfe zur veralteten Telebit.js-CLI](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [LocalXpose-Dokumentation](https://localxpose.gitbook.io/docs)
- [8] [Expose – Websites freigeben](https://expose.dev/docs/client/sharing)
- [9] [Expose – TCP-Ports freigeben](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [Repository localtunnel/localtunnel](https://github.com/localtunnel/localtunnel)
- [11] [Cloudflare-Dokumentation – Cloudflare Tunnel einrichten](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Überblick über Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [13] [Cloudflare-Dokumentation – Nützliche Tunnel-Befehle](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Cloudflare-Dokumentation – Routing](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Cloudflare-Dokumentation – Konfigurationsdatei](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Cloudflare-Access-Richtlinien](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Cloudflare-Dokumentation – Ausführungsparameter](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Tailscale-Serve-Befehl](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Tailscale-Funnel-Befehl](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [Repository fatedier/frp – Fast Reverse Proxy](https://github.com/fatedier/frp)
- [21] [Pinggy-Dokumentation – Verwendung](https://pinggy.io/docs/usages/)
- [22] [Pinggy – Einfache Localhost-Tunnel](https://pinggy.io/)
- [23] [Proofpoint – Bedrohungsakteur missbraucht Cloudflare-Tunnel zur Auslieferung von RATs](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
- [24] [Cloudflare-Dokumentation – Tunnel-Routing und unterstützte Protokolle](https://developers.cloudflare.com/tunnel/concepts/routing/)
{{#include ../banners/hacktricks-training.md}}
