# Izlaganje lokalnog na Internet

{{#include ../../banners/hacktricks-training.md}}

**Cilj ove stranice je da predloži alternative koje omogućavaju NAJMANJE izlaganje lokalnih sirovih TCP portova i lokalnih web servisa (HTTP) na Internet, BEZ potrebe za instalacijom bilo čega na drugom serveru (samo lokalno ako je potrebno).**

## **Serveo**

[https://serveo.net/](https://serveo.net/) omogućava nekoliko HTTP i port forwarding funkcija **besplatno**.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Sa [https://www.socketxp.com/download](https://www.socketxp.com/download), omogućava izlaganje tcp i http:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

Sa [https://ngrok.com/](https://ngrok.com/), omogućava izlaganje http i tcp portova:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

Sa [https://telebit.cloud/](https://telebit.cloud/) možete izložiti http i tcp portove:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Sa [https://localxpose.io/](https://localxpose.io/), omogućava nekoliko http i port forwarding funkcija **besplatno**.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

Sa [https://expose.dev/](https://expose.dev/) omogućava izlaganje http i tcp portova:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

Prema [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) omogućava besplatno izlaganje http:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Cloudflare's `cloudflared` CLI može da kreira neautentifikovane "Quick" tunele za brze demo prikaze ili imenovane tunele vezane za vaš domain/hostnames. Podržava HTTP(S) reverse proxies kao i raw TCP mappings rutirane kroz Cloudflare's edge.
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
Named tunnels omogućavaju da definišete više ingress pravila (HTTP, SSH, RDP, itd.) u `tunnel.yml`, podržavaju politike pristupa po servisu putem Cloudflare Access i mogu se pokretati kao systemd containers radi perzistentnosti. Quick Tunnels su anonimni i efemerni — odlični za phishing payload staging ili webhook testove, ali Cloudflare ne garantuje uptime.

## Tailscale Funnel / Serve

Tailscale v1.52+ uvodi objedinjene `tailscale serve` (deljenje unutar tailnet) i `tailscale funnel` (objavljivanje na širi internet) tokove rada. Obe komande mogu reverse proxy HTTP(S) ili prosleđivati raw TCP uz automatski TLS i kratke `*.ts.net` hostnames.
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Koristite `--bg` da sačuvate konfiguraciju bez potrebe da proces ostane u foreground-u, i `tailscale funnel status` da proverite koje usluge su dostupne sa javnog interneta. Pošto Funnel terminira TLS na lokalnom čvoru, bilo koji promptovi za kredencijale, headers ili mTLS enforcement mogu ostati pod vašom kontrolom.

## Fast Reverse Proxy (frp)

`frp` je self-hosted opcija gde vi kontrolišete rendezvous server (`frps`) i klijent (`frpc`). Odličan je za red teams koji već poseduju VPS i žele determinističke domene/portove.

<details>
<summary>Primer frps/frpc konfiguracije</summary>
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

Nedavne verzije dodaju QUIC transport, token/OIDC auth, bandwidth caps, health checks i Go-template-based range mappings — korisno za brzo podizanje više listeners koji map back na implants na različitim hosts.

## Pinggy (SSH-based)

Pinggy pruža SSH-accessible tunnels preko TCP/443, pa radi čak i iza captive proxies koje dozvoljavaju samo HTTPS. Sesije traju 60 minuta na free tier i mogu se skriptovati za brze demo-e ili webhook relays.
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
Možete zatražiti prilagođene domene i duže trajanje tunnels na paid tier-u, ili automatski reciklirati tunnels tako što ćete komandu izvršavati u petlji.

## Threat intel & OPSEC notes

Napadači su sve češće zloupotrebljavali ephemeral tunneling (posebno Cloudflare-ove unauthenticated `trycloudflare.com` endpoints) kako bi plasirali Remote Access Trojan payloads i prikrili C2 infrastrukturu. Proofpoint je pratio kampanje od februara 2024. koje su distribuirale AsyncRAT, Xworm, VenomRAT, GuLoader i Remcos tako što su usmeravale download stages na kratkotrajne TryCloudflare URL-ove, što je tradicionalne static blocklists činilo znatno manje efikasnim. Razmotrite proaktivno rotiranje tunnels i domains, ali takođe pratite karakteristične spoljne DNS lookups ka tunneleru koji koristite kako biste rano uočili blue-team detekciju ili pokušaje blokiranja infrastrukture.

## References

- [Cloudflare Docs - Create a locally-managed tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [Proofpoint - Threat Actor Abuses Cloudflare Tunnels to Deliver RATs](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)

{{#include ../../banners/hacktricks-training.md}}
