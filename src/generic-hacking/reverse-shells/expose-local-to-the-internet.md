# Fichua local kwenye internet

{{#include ../../banners/hacktricks-training.md}}

**Lengo la ukurasa huu ni kupendekeza njia mbadala zinazoruhusu KUFICHUA angalau raw TCP ports za local na webs za local (HTTP) kwenye internet BILA kuhitaji kusakinisha chochote kwenye server nyingine (ikiwa inahitajika, ni kwenye local pekee).**

## **Serveo**

Nyaraka za Serveo zinaeleza SSH forwarding kwa HTTP endpoints na private/public TCP forwarding; kuomba public TCP port isiyo ya 80/443 (ikiwemo port 0 kwa port ya nasibu) kunahitaji user aliyesajiliwa.<sup>[[1]](#references)</sup>
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Mwongozo wa kuanza wa SocketXP unaandika `socketxp connect tcp://localhost:22` na `socketxp connect http://localhost:8080` kwa tunnels za TCP na HTTP; agent hu-authenticate kwa portal token kwanza.<sup>[[2]](#references)</sup>
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

CLI ya ngrok inaeleza HTTP na TCP tunnels; FAQ yake inasema kuwa TCP endpoints za free-tier zinahitaji payment method halali na kwamba kadi haitozwi.<sup>[[3]](#references)[[4]](#references)</sup>
```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```
## Telebit

Nyaraka za msaada za zamani za Telebit.js CLI zinaeleza `telebit http <port>` kwa forwarding ya HTTPS na `telebit tcp <local> [remote]` kwa raw TCP; upatikanaji hutegemea deployment na relay.<sup>[[5]](#references)</sup>
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Tovuti ya sasa ya LocalXpose inaandika `loclx tunnel http --to 3000`, inaorodhesha usaidizi wa HTTP/TLS/TCP/UDP, na inasema mpango wa bure unahusisha matumizi ya kibinafsi/matumizi mepesi ya kibiashara, huku TCP tunneling ikiwa ni uwezo wa mpango unaolipiwa.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```
## Expose

Expose documents `expose share` kwa ajili ya URL za HTTP/HTTPS za ndani na command ya `expose share-port` ya PRO-only kwa TCP ports.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```
## Localtunnel

Repository rasmi ya localtunnel inaeleza jinsi ya kuonyesha localhost kwa ajili ya testing na inaandika command ya NPX iliyo hapa chini.<sup>[[10]](#references)</sup>
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Nyaraka za sasa za Cloudflare zinaonyesha tunnels za "Quick" zisizohitaji uthibitishaji kwa ajili ya local development, na muhtasari wa bidhaa unataja HTTP, HTTPS, TCP, SSH, na RDP miongoni mwa protocols zinazotumika za kuchapishwa.<sup>[[11]](#references)[[12]](#references)</sup>

Kwa tunnel yenye jina inayosimamiwa locally, Cloudflare inaandika workflow ya `tunnel login`, `create`, `route dns`, na `--config ... run ...`.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```
Named tunnels zinaweza kufafanua ingress rules nyingi katika YAML; sera za Cloudflare Access zinaweza kudhibiti ufikiaji wa applications zilizochapishwa, na Cloudflare inaandika njia za deployment za service na Docker kwa kuendesha connectors. Quick Tunnels ni tunnels za majaribio za muda zisizohitaji utambulisho, zenye kikomo cha requests 200 kwa wakati mmoja na zisizounga mkono Server-Sent Events (SSE).<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

CLI ya sasa ya Tailscale hutumia Serve kwa sharing inayopatikana kwenye tailnet pekee, na Funnel kwa sharing ya hadharani. Commands zinaunga mkono targets za HTTP/HTTPS reverse-proxy na TCP forwarding; raw TCP mode ya Funnel imewekewa kikomo kwenye ports 443, 8443, na 10000.<sup>[[18]](#references)[[19]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Tumia `--bg` kuhifadhi usanidi bila kuweka process ya foreground, na utumie `tailscale funnel status` kukagua ni services zipi zinapatikana kutoka kwenye public internet. Kwa targets za HTTPS Funnel, Tailscale inaeleza kuwa TLS termination hufanyika kwenye local node kabla ya request ku-forwardiwa kwenye local service.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp` ni chaguo la self-hosted ambapo unadhibiti rendezvous server (`frps`) na client (`frpc`); documentation yake inaeleza jinsi ya ku-forward local services zilizo nyuma ya NAT au firewall kwa kutumia remote ports/domains zinazotabirika.<sup>[[20]](#references)</sup>

<details>
<summary>Sample frps/frpc configuration</summary>
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

Nyaraka za sasa za mradi zinajumuisha QUIC transport, token/OIDC authentication, bandwidth limits, health checks, na Go-template range mappings—angalia release inayolingana na deployment yako kabla ya kutumia chaguo lolote kati ya hayo.<sup>[[20]](#references)</sup>

## Pinggy (SSH-based)

Pinggy inaeleza SSH reverse forwarding kupitia port 443, hivyo inaweza kufanya kazi kwenye networks ambapo outbound SSH kwenye port 22 imezuiwa. Free plan yake huisha baada ya dakika 60 na hutumia URL mpya baada ya kuunganisha tena, huku Pro ikiongeza persistent tunnels na custom domains.<sup>[[21]](#references)[[22]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```
Unaweza kuomba custom domains na persistent tunnels kwenye Pro.<sup>[[22]](#references)</sup> Unaweza kurejesha temporary tunnels kiotomatiki kwa kufunga command ndani ya loop.

## Threat intel & OPSEC notes

Adversaries wametumia vibaya ephemeral tunneling, ikiwemo endpoints za Cloudflare zisizohitaji authentication za `trycloudflare.com`, ili kuwasilisha Remote Access Trojans kupitia temporary infrastructure. Proofpoint iliripoti shughuli zilizoonekana kwa mara ya kwanza Februari 2024 zilizohusisha Xworm, AsyncRAT, VenomRAT, GuLoader, na Remcos, na ikaeleza kuwa temporary tunnels hufanya ulinzi unaotegemea static blocklists kuwa mgumu zaidi.<sup>[[23]](#references)</sup> Fikiria kuzungusha tunnels na domains kwa uangalifu kabla ya tatizo kutokea, na fuatilia external DNS lookups zinazoelekezwa kwa tunneler unayotumia ili uweze kugundua mapema blue-team detection au majaribio ya kuzuia infrastructure.

## References

- [1] [Nyaraka za Serveo](https://serveo.net/docs/)
- [2] [Nyaraka za SocketXP - Kuanza](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [ngrok Agent Command Line Interface](https://ngrok.com/docs/agent/cli)
- [4] [Maswali Yanayoulizwa Mara kwa Mara kuhusu ngrok](https://ngrok.com/docs/faq)
- [5] [Msaada wa Telebit.js legacy CLI](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [Nyaraka za LocalXpose](https://localxpose.gitbook.io/docs)
- [8] [Expose - Kushiriki sites](https://expose.dev/docs/client/sharing)
- [9] [Expose - Kushiriki TCP ports](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [repository ya localtunnel/localtunnel](https://github.com/localtunnel/localtunnel)
- [11] [Nyaraka za Cloudflare - Kuweka Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Muhtasari wa Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [13] [Nyaraka za Cloudflare - Useful tunnel commands](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Nyaraka za Cloudflare - Routing](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Nyaraka za Cloudflare - Configuration file](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Sera za Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Nyaraka za Cloudflare - Run parameters](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Tailscale Serve command](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Tailscale Funnel command](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [repository ya fatedier/frp - Fast Reverse Proxy](https://github.com/fatedier/frp)
- [21] [Nyaraka za Pinggy - Matumizi](https://pinggy.io/docs/usages/)
- [22] [Pinggy - Simple Localhost Tunnels](https://pinggy.io/)
- [23] [Proofpoint - Threat Actor Abuses Cloudflare Tunnels to Deliver RATs](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
{{#include ../../banners/hacktricks-training.md}}
