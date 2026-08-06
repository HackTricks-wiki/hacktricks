# Fichua local kwenye internet

{{#include ../../banners/hacktricks-training.md}}

**Lengo la ukurasa huu ni kupendekeza njia mbadala zinazoruhusu angalau kufichua raw TCP ports za local na webs za local (HTTP) kwenye internet BILA kuhitaji kusakinisha chochote kwenye server nyingine (isipokuwa kwenye local ikiwa inahitajika).**

## **Serveo**

Kutoka [https://serveo.net/](https://serveo.net/), inaruhusu vipengele kadhaa vya http na port forwarding **bila malipo**.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Kutoka [https://www.socketxp.com/download](https://www.socketxp.com/download), inaruhusu kuweka wazi tcp na http:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

Kutoka [https://ngrok.com/](https://ngrok.com/), inaruhusu ku-expose http na tcp ports:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

Kutoka [https://telebit.cloud/](https://telebit.cloud/) unaweza ku-expose http na tcp ports:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Kutoka [https://localxpose.io/](https://localxpose.io/), inaruhusu vipengele kadhaa vya http na port forwarding **bila malipo**.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

Kutoka [https://expose.dev/](https://expose.dev/) unaweza ku-expose port za http na tcp:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

Kupitia [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel), unaweza ku-expose http bila malipo:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

CLI ya `cloudflared` ya Cloudflare inaweza kuunda tunnels za "Quick" zisizohitaji uthibitishaji kwa demos za haraka, au tunnels zenye majina zilizounganishwa na domain/hostnames zako. Inatumia reverse proxies za HTTP(S) pamoja na mappings za TCP ghafi zinazoelekezwa kupitia edge ya Cloudflare.<sup>[[1]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
Named tunnels hukuruhusu kufafanua ingress rules nyingi (HTTP, SSH, RDP, n.k.) ndani ya `tunnel.yml`, kuunga mkono access policies za kila service kupitia Cloudflare Access, na zinaweza kuendeshwa kama systemd containers kwa persistence. Quick Tunnels hazitambuliki na ni za muda mfupi—zinafaa kwa phishing payload staging au webhook tests, lakini Cloudflare haihakikishi uptime.<sup>[[1]](#references)</sup>

## Tailscale Funnel / Serve

Tailscale v1.52+ inakuja na workflows zilizounganishwa za `tailscale serve` (kushiriki ndani ya tailnet) na `tailscale funnel` (kuchapisha kwenye internet pana). Amri zote mbili zinaweza kutumia reverse proxy kwa HTTP(S) au ku-forward raw TCP zikiwa na automatic TLS na hostnames fupi za `*.ts.net`.<sup>[[3]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Tumia `--bg` kuhifadhi configuration bila kuweka process ya foreground, na `tailscale funnel status` kukagua ni services zipi zinaweza kufikiwa kutoka public internet. Kwa kuwa Funnel hukatisha TLS kwenye local node, credential prompts, headers, au mTLS enforcement yoyote inaweza kubaki chini ya udhibiti wako.

## Fast Reverse Proxy (frp)

`frp` ni option ya self-hosted ambapo unadhibiti rendezvous server (`frps`) na client (`frpc`). Ni nzuri kwa red teams ambazo tayari zinamiliki VPS na zinataka domains/ports zenye tabia inayotabirika.

<details>
<summary>Configuration ya mfano ya frps/frpc</summary>
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

Matoleo ya hivi karibuni yanaongeza usafirishaji wa QUIC, token/OIDC auth, vikomo vya bandwidth, health checks, na range mappings zinazotumia Go templates—ni muhimu kwa kusimamisha kwa haraka listeners wengi wanaounganisha nyuma na implants kwenye hosts tofauti.<sup>[[4]](#references)</sup>

## Pinggy (SSH-based)

Pinggy hutoa tunnels zinazoweza kufikiwa kupitia SSH kwenye TCP/443, hivyo hufanya kazi hata nyuma ya captive proxies zinazoruhusu HTTPS pekee. Sessions hudumu kwa dakika 60 kwenye free tier na zinaweza kuandikwa kwa script kwa ajili ya demos za haraka au webhook relays.<sup>[[5]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
Unaweza kuomba domains maalum na tunnels zenye muda mrefu zaidi kwenye paid tier, au uanze upya tunnels automatically kwa kuweka command ndani ya loop.

## Threat intel & OPSEC notes

Wapinzani wamezidi kutumia vibaya ephemeral tunneling (hasa endpoints za Cloudflare zisizohitaji authentication za `trycloudflare.com`) kuandaa payloads za Remote Access Trojan na kuficha C2 infrastructure. Proofpoint ilifuatilia campaigns tangu Februari 2024 zilizotuma AsyncRAT, Xworm, VenomRAT, GuLoader, na Remcos kwa kuelekeza download stages kwenye URLs za TryCloudflare zenye muda mfupi, jambo lililofanya static blocklists za kawaida zisiwe na ufanisi mkubwa. Fikiria kuzungusha tunnels na domains proactively, lakini pia fuatilia external DNS lookups zinazoashiria tunneler unayotumia ili uweze kugundua mapema blue-team detection au majaribio ya kuzuia infrastructure.<sup>[[2]](#references)</sup>

## References

- [1] [Cloudflare Docs - Create a locally-managed tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [2] [Proofpoint - Threat Actor Abuses Cloudflare Tunnels to Deliver RATs](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
- [3] [Tailscale - Reintroducing Serve and Funnel](https://tailscale.com/blog/reintroducing-serve-funnel)
- [4] [fatedier/frp - Fast Reverse Proxy repository](https://github.com/fatedier/frp)
- [5] [Pinggy Documentation - Usage](https://pinggy.io/docs/usages/)

{{#include ../../banners/hacktricks-training.md}}
