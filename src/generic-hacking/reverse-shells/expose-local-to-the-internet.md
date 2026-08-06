# Stel plaaslike dienste aan die internet bloot

{{#include ../../banners/hacktricks-training.md}}

**Die doel van hierdie bladsy is om alternatiewe voor te stel waarmee plaaslike raw TCP-poorte en plaaslike webdienste (HTTP) TEN MINSTE aan die internet blootgestel kan word SONDER dat enigiets op die ander bediener geïnstalleer hoef te word (slegs plaaslik, indien nodig).**

## **Serveo**

Vanaf [https://serveo.net/](https://serveo.net/) bied dit verskeie HTTP- en port forwarding-kenmerke **gratis**.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Vanaf [https://www.socketxp.com/download](https://www.socketxp.com/download), maak dit moontlik om tcp en http bloot te stel:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

Vanaf [https://ngrok.com/](https://ngrok.com/) kan jy http- en tcp-poorte blootstel:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

Vanaf [https://telebit.cloud/](https://telebit.cloud/) kan jy http- en tcp-poorte blootstel:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Vanaf [https://localxpose.io/](https://localxpose.io/) bied dit verskeie http- en port forwarding-funksies **gratis**.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

Vanaf [https://expose.dev/](https://expose.dev/) kan jy http- en tcp-poorte blootstel:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

Vanaf [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) laat dit jou toe om http gratis bloot te stel:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Cloudflare se `cloudflared` CLI kan ongeauthentiseerde "Quick"-tunnels skep vir vinnige demos, of benoemde tunnels wat aan jou eie domein/gasheername gekoppel is. Dit ondersteun HTTP(S)-omgekeerde proxy's sowel as rou TCP-mappings wat deur Cloudflare se edge gerouteer word.<sup>[[1]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
Named tunnels laat jou toe om verskeie ingress-reëls (HTTP, SSH, RDP, ens.) binne `tunnel.yml` te definieer, per-diens-toegangsbeleide via Cloudflare Access te ondersteun, en as systemd-containers te loop vir persistence. Quick Tunnels is anoniem en ephemeral—ideaal vir phishing payload staging of webhook-toetse, maar Cloudflare waarborg nie uptime nie.<sup>[[1]](#references)</sup>

## Tailscale Funnel / Serve

Tailscale v1.52+ verskaf unified `tailscale serve` (deel binne die tailnet) en `tailscale funnel` (publiseer na die breër internet)-workflows. Albei commands kan HTTP(S) reverse proxy of raw TCP forward, met automatic TLS en kort `*.ts.net`-hostnames.<sup>[[3]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Gebruik `--bg` om die konfigurasie te behou sonder om ’n foreground process aan die gang te hou, en `tailscale funnel status` om te oudit watter dienste vanaf die publieke internet bereikbaar is. Omdat Funnel TLS op die plaaslike node beëindig, kan enige credential prompts, headers of mTLS enforcement onder jou beheer bly.

## Fast Reverse Proxy (frp)

`frp` is ’n self-hosted opsie waar jy die rendezvous-bediener (`frps`) en die kliënt (`frpc`) beheer. Dit is ideaal vir red teams wat reeds ’n VPS besit en deterministiese domeine/poorte wil hê.

<details>
<summary>Voorbeeld van frps/frpc-konfigurasie</summary>
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

Onlangse vrystellings voeg QUIC-transport, token/OIDC-auth, bandwidth caps, health checks en Go-template-based range mappings by—nuttig om vinnig veelvuldige listeners op te stel wat terugkarteer na implants op verskillende hosts.<sup>[[4]](#references)</sup>

## Pinggy (SSH-based)

Pinggy verskaf SSH-accessible tunnels oor TCP/443, dus werk dit selfs agter captive proxies wat slegs HTTPS toelaat. Sessies duur 60 minute op die free tier en kan gescript word vir vinnige demos of webhook relays.<sup>[[5]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
Jy kan custom domains en tunnels met ’n langer leeftyd op die betaalde vlak aanvra, of tunnels outomaties herwin deur die command in ’n loop te plaas.

## Bedreigingsintelligensie- en OPSEC-notas

Adversaries het ephemeral tunneling toenemend misbruik, veral Cloudflare se unauthenticated `trycloudflare.com` endpoints, om Remote Access Trojan payloads te stageer en C2 infrastructure te versteek. Proofpoint het sedert Februarie 2024 campaigns opgespoor wat AsyncRAT, Xworm, VenomRAT, GuLoader en Remcos versprei het deur download stages na kortlewende TryCloudflare URLs te wys, wat tradisionele static blocklists veel minder effektief maak. Oorweeg dit om tunnels en domains proaktief te roteer, maar monitor ook vir kenmerkende external DNS lookups na die tunneler wat jy gebruik, sodat jy blue-team detection of pogings om infrastructure te blokkeer vroeg kan raaksien.<sup>[[2]](#references)</sup>

## Verwysings

- [1] [Cloudflare Docs - Skep ’n lokaal bestuurde tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [2] [Proofpoint - Threat Actor Abuse Cloudflare Tunnels om RATs te lewer](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
- [3] [Tailscale - Serve en Funnel word heringestel](https://tailscale.com/blog/reintroducing-serve-funnel)
- [4] [fatedier/frp - Fast Reverse Proxy repository](https://github.com/fatedier/frp)
- [5] [Pinggy Documentation - Gebruik](https://pinggy.io/docs/usages/)

{{#include ../../banners/hacktricks-training.md}}
