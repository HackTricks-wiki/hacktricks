# Kufikisha huduma za ndani kwenye intaneti

{{#include ../../banners/hacktricks-training.md}}

**Lengo la ukurasa huu ni kupendekeza mbadala zinazowezesha, ANGALAU, kufunua bandari za TCP za ndani na wavuti za ndani (HTTP) kwenye intaneti BILA ya kuhitaji kusakinisha chochote kwenye server nyingine (tu kwenye mashine ya ndani ikiwa inahitajika).**

## **Serveo**

From [https://serveo.net/](https://serveo.net/), inaruhusu huduma kadhaa za http na port forwarding **bila malipo**.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Kutoka [https://www.socketxp.com/download](https://www.socketxp.com/download), inaruhusu kufichua tcp na http:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

Kutoka [https://ngrok.com/](https://ngrok.com/), inaruhusu kufichua http na tcp ports:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

Kutoka [https://telebit.cloud/](https://telebit.cloud/), inaruhusu expose http na tcp ports:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Kutoka kwa [https://localxpose.io/](https://localxpose.io/), inaruhusu vipengele kadhaa vya http na port forwarding **bila malipo**.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

Kutoka kwa [https://expose.dev/](https://expose.dev/), inaruhusu kufunua porti za http na tcp:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

Kutoka [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) inaruhusu kufungua http kwa bure:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

CLI ya Cloudflare `cloudflared` inaweza kuunda tunnels zisizo na uthibitisho za "Quick" kwa demos za haraka au tunnels zilizopewa majina zinazofungwa kwenye domain/hostnames yako. Inaunga mkono HTTP(S) reverse proxies pamoja na raw TCP mappings zinazopitishwa kupitia edge ya Cloudflare.
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
Tuneli zilizopewa majina zinakuwezesha kufafanua masharti kadhaa za ingress (HTTP, SSH, RDP, n.k.) ndani ya `tunnel.yml`, zinaunga mkono sera za upatikanaji kwa kila huduma kupitia Cloudflare Access, na zinaweza kuendeshwa kama systemd containers kwa udumu. Quick Tunnels ni anonymous na ephemeral—zuri kwa staging ya payload za phishing au majaribio ya webhook, lakini Cloudflare haisi kutoa dhamana ya upatikanaji.

## Tailscale Funnel / Serve

Tailscale v1.52+ inakuja na workflows zilizounganishwa za `tailscale serve` (shiriki ndani ya tailnet) na `tailscale funnel` (chapisha kwenye mtandao mpana). Amri zote mbili zinaweza kufanya reverse proxy ya HTTP(S) au kupeleka raw TCP kwa TLS ya otomatiki na hostnames fupi za `*.ts.net`.
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Tumia `--bg` kuhifadhi usanidi bila kuendelea kuweka mchakato wa mbele, na `tailscale funnel status` kukagua ni huduma gani zinazoweza kufikiwa kutoka kwenye intaneti ya umma. Kwa sababu Funnel inamaliza TLS kwenye node ya ndani, maombi yoyote ya vielezo vya kuingia, headers, au utekelezaji wa mTLS yanaweza kubaki chini ya udhibiti wako.

## Fast Reverse Proxy (frp)

`frp` ni chaguo linalojiendesha mwenyewe ambapo unadhibiti seva ya rendezvous (`frps`) na mteja (`frpc`). Inafaa kwa red teams ambazo tayari zinamiliki VPS na zinataka domains/ports zinazotabirika.

<details>
<summary>Mfano wa usanidi wa frps/frpc</summary>
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

Matoleo ya hivi karibuni yameongeza QUIC transport, token/OIDC auth, bandwidth caps, health checks, na Go-template-based range mappings — zikitumika kwa kuanzisha haraka multiple listeners ambazo map back to implants on different hosts.

Pinggy hutoa SSH-accessible tunnels juu ya TCP/443, kwa hivyo inafanya kazi hata nyuma ya captive proxies zinazoruhusu tu HTTPS. Sessions hudumu 60 minutes kwenye free tier na zinaweza ku-scripted kwa quick demos au webhook relays.
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
Unaweza kuomba domains maalum na tunnels zenye maisha marefu kwenye tier iliyolipwa, au kuzirudia tunnels moja kwa moja kwa kuzungusha amri ndani ya loop.

## Threat intel & OPSEC notes

Waasi wamekuwa wakitumia vibaya ephemeral tunneling kwa wingi (hasa endpoints zisizothibitishwa za Cloudflare `trycloudflare.com`) ili kuweka Remote Access Trojan payloads na kuficha miundombinu ya C2. Proofpoint imefuatilia kampeni tangu Februari 2024 ambazo zilisambaza AsyncRAT, Xworm, VenomRAT, GuLoader, na Remcos kwa kuelekeza hatua za download kwenye TryCloudflare URLs za muda mfupi, na kuifanya blocklists za jadi zisifanye kazi kwa ufanisi. Fikiria kuzungusha tunnels na domains kwa kujitayarisha, lakini pia fuatilia external DNS lookups zinazoweza kuashiria tunneler unayotumia ili uweze kugundua blue-team detection au jaribio la kuzuia miundombinu mapema.

## References

- [Cloudflare Docs - Create a locally-managed tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [Proofpoint - Threat Actor Abuses Cloudflare Tunnels to Deliver RATs](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)

{{#include ../../banners/hacktricks-training.md}}
