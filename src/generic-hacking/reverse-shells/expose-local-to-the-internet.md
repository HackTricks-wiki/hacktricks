# Blootstel local aan die internet

{{#include ../../banners/hacktricks-training.md}}

**Die doel van hierdie bladsy is om alternatiewe voor te stel wat TEN MINSTE toelaat om local rou TCP-porte en local webs (HTTP) na die internet bloot te stel SONDER om enigiets op die ander server te hoef te installeer (slegs op die local indien nodig).**

## **Serveo**

Vanaf [https://serveo.net/](https://serveo.net/) laat dit verskeie http- en port forwarding funksies toe **gratis**.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Vanaf [https://www.socketxp.com/download](https://www.socketxp.com/download), dit laat toe om tcp en http:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

Vanaf [https://ngrok.com/](https://ngrok.com/), dit laat toe om http en tcp ports bloot te stel:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

Vanaf [https://telebit.cloud/](https://telebit.cloud/) maak dit moontlik om http- en tcp-ports bloot te stel:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Vanaf [https://localxpose.io/](https://localxpose.io/), dit bied verskeie http- en port forwarding-kenmerke **gratis**.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

Vanaf [https://expose.dev/](https://expose.dev/) laat dit toe om http- en tcp-poorte bloot te stel:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

Vanaf [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) maak dit moontlik om HTTP gratis bloot te stel:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Cloudflare se `cloudflared` CLI kan ongeauthentiseerde "Quick" tunnels skep vir vinnige demos of benoemde tunnels aan jou eie domain/hostnames gebind. Dit ondersteun HTTP(S) reverse proxies sowel as raw TCP mappings wat deur Cloudflare se edge gerouteer word.
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
Genaamde tunnels laat jou toe om verskeie ingress-reëls (HTTP, SSH, RDP, ens.) binne `tunnel.yml` te definieer, ondersteun per-diens toegangspolisse via Cloudflare Access, en kan as systemd containers loop vir persistentie. Quick Tunnels is anoniem en vlugtig — ideaal vir phishing payload staging of webhook-toetse, maar Cloudflare waarborg nie uptime nie.

## Tailscale Funnel / Serve

Tailscale v1.52+ bring 'n verenigde `tailscale serve` (deel binne die tailnet) en `tailscale funnel` (publiseer na die breër internet) werkvloei. Albei opdragte kan as reverse proxy HTTP(S) bedien of rou TCP deurstuur met outomatiese TLS en kort `*.ts.net` gasheernames.
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Gebruik `--bg` om die konfigurasie te behou sonder om 'n voorgrondproses aan die gang te hou, en `tailscale funnel status` om te oudit watter dienste vanaf die openbare internet bereikbaar is. Omdat Funnel TLS op die lokale node beëindig, kan enige kredensiaalprompts, headers of mTLS-afdwinging onder jou beheer bly.

## Fast Reverse Proxy (frp)

`frp` is 'n self-hosted opsie waar jy die rendezvous server (`frps`) en die kliënt (`frpc`) beheer. Dit is ideaal vir red teams wat reeds 'n VPS besit en deterministiese domeine/porte wil hê.

<details>
<summary>Voorbeeld frps/frpc-konfigurasie</summary>
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

Onlangse vrystellings voeg QUIC transport, token/OIDC auth, bandwydtegrense, health checks, en Go-template-based range mappings by—nuttig om vinnig verskeie listeners op te stel wat terugkoppel na implants op verskillende hosts.

## Pinggy (SSH-based)

Pinggy bied SSH-accessible tunnels oor TCP/443, sodat dit selfs agter captive proxies werk wat slegs HTTPS toelaat. Sessies duur 60 minute op die free tier en kan geskrip word vir vinnige demo's of webhook relays.
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
Jy kan pasgemaakte domeine en langer-lewendige tunnels op die betaalde vlak versoek, of tunnels outomaties herwin deur die opdrag in 'n lus te plaas.

## Dreigingsintel & OPSEC notas

Bedreigers het toenemend ephemeral tunneling misbruik (veral Cloudflare se ongeverifieerde `trycloudflare.com` endpunte) om Remote Access Trojan payloads te stage en C2-infrastruktuur te verberg. Proofpoint het sedert Februarie 2024 veldtogte gevolg wat AsyncRAT, Xworm, VenomRAT, GuLoader, and Remcos gepush het deur aflaaistadia na kortlewendige TryCloudflare URLs te wys, wat tradisionele statiese bloklysies baie minder effektief maak. Oorweeg om tunnels en domeine proaktief te roteer, maar hou ook dop vir tipiese eksterne DNS-opvraginge na die tunneler wat jy gebruik sodat jy blue-team detection of pogings tot infrastruktuurblokkering vroeg kan opspoor.

## Verwysings

- [Cloudflare Docs - Create a locally-managed tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [Proofpoint - Threat Actor Abuses Cloudflare Tunnels to Deliver RATs](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)

{{#include ../../banners/hacktricks-training.md}}
