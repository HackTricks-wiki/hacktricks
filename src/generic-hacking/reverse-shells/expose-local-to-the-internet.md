# local को internet पर expose करें

{{#include ../../banners/hacktricks-training.md}}

**इस पेज का लक्ष्य ऐसे alternatives प्रस्तुत करना है जो कम से कम local raw TCP ports और local webs (HTTP) को internet पर expose करने की अनुमति दें, और इसके लिए दूसरे server में कुछ भी install करने की आवश्यकता न हो (यदि आवश्यक हो तो केवल local में)।**

## **Serveo**

[https://serveo.net/](https://serveo.net/) से, यह कई http और port forwarding features **निःशुल्क** उपलब्ध कराता है।
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

[https://www.socketxp.com/download](https://www.socketxp.com/download) से tcp और http को expose करने की अनुमति मिलती है:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

[https://ngrok.com/](https://ngrok.com/) से, यह HTTP और TCP ports को expose करने की अनुमति देता है:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

[https://telebit.cloud/](https://telebit.cloud/) से HTTP और TCP ports को expose किया जा सकता है:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

[https://localxpose.io/](https://localxpose.io/) से **मुफ्त** में कई http और port forwarding सुविधाएं उपलब्ध होती हैं।
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

[https://expose.dev/](https://expose.dev/) से http और tcp ports को expose किया जा सकता है:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

[https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) से यह http को मुफ्त में expose करने की अनुमति देता है:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Cloudflare का `cloudflared` CLI तेज़ demos के लिए unauthenticated "Quick" tunnels या आपके अपने domain/hostnames से bound named tunnels बना सकता है। यह HTTP(S) reverse proxies के साथ-साथ Cloudflare's edge के माध्यम से routed raw TCP mappings को भी support करता है।<sup>[[1]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
Named tunnels आपको `tunnel.yml` के अंदर कई ingress rules (HTTP, SSH, RDP आदि) define करने देते हैं, Cloudflare Access के माध्यम से per-service access policies का समर्थन करते हैं, और persistence के लिए systemd containers के रूप में चल सकते हैं। Quick Tunnels anonymous और ephemeral होते हैं—phishing payload staging या webhook tests के लिए उपयोगी, लेकिन Cloudflare uptime की guarantee नहीं देता।<sup>[[1]](#references)</sup>

## Tailscale Funnel / Serve

Tailscale v1.52+ में unified `tailscale serve` (tailnet के अंदर share करना) और `tailscale funnel` (विस्तृत internet पर publish करना) workflows शामिल हैं। दोनों commands automatic TLS और छोटे `*.ts.net` hostnames के साथ HTTP(S) को reverse proxy कर सकते हैं या raw TCP को forward कर सकते हैं।<sup>[[3]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
`--bg` का उपयोग foreground process को चालू रखे बिना configuration को persist करने के लिए करें, और public internet से reachable services का audit करने के लिए `tailscale funnel status` चलाएँ। क्योंकि Funnel local node पर TLS terminate करता है, इसलिए credential prompts, headers या mTLS enforcement आपके नियंत्रण में रह सकते हैं।

## Fast Reverse Proxy (frp)

`frp` एक self-hosted विकल्प है, जिसमें आप rendezvous server (`frps`) और client (`frpc`) को नियंत्रित करते हैं। यह उन red teams के लिए उपयोगी है जिनके पास पहले से VPS है और जो deterministic domains/ports चाहते हैं।

<details>
<summary>Sample frps/frpc configuration</summary>
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

हालिया releases में QUIC transport, token/OIDC auth, bandwidth caps, health checks और Go-template-based range mappings जोड़े गए हैं—ये अलग-अलग hosts पर implants से वापस map होने वाले कई listeners को जल्दी से शुरू करने के लिए उपयोगी हैं।<sup>[[4]](#references)</sup>

## Pinggy (SSH-based)

Pinggy TCP/443 पर SSH-accessible tunnels प्रदान करता है, इसलिए यह captive proxies के पीछे भी काम करता है जो केवल HTTPS की अनुमति देते हैं। Free tier में sessions 60 मिनट तक चलते हैं और इन्हें quick demos या webhook relays के लिए script किया जा सकता है।<sup>[[5]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
आप paid tier पर custom domains और longer-lived tunnels request कर सकते हैं, या command को loop में wrap करके tunnels को automatically recycle कर सकते हैं।

## Threat intel और OPSEC notes

Adversaries ने ephemeral tunneling का increasingly abuse किया है (विशेष रूप से Cloudflare के unauthenticated `trycloudflare.com` endpoints का), ताकि Remote Access Trojan payloads को stage किया जा सके और C2 infrastructure को छिपाया जा सके। Proofpoint ने February 2024 से ऐसी campaigns को track किया है, जिनमें AsyncRAT, Xworm, VenomRAT, GuLoader और Remcos को short-lived TryCloudflare URLs पर download stages point करके deliver किया गया, जिससे traditional static blocklists काफी कम effective हो गईं। Tunnels और domains को proactively rotate करने पर विचार करें, लेकिन साथ ही आपके द्वारा उपयोग किए जा रहे tunneler के लिए होने वाले telltale external DNS lookups को भी monitor करें, ताकि blue-team detection या infrastructure blocking attempts को early stage पर identify किया जा सके।<sup>[[2]](#references)</sup>

## References

- [1] [Cloudflare Docs - Create a locally-managed tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [2] [Proofpoint - Threat Actor Abuses Cloudflare Tunnels to Deliver RATs](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
- [3] [Tailscale - Reintroducing Serve and Funnel](https://tailscale.com/blog/reintroducing-serve-funnel)
- [4] [fatedier/frp - Fast Reverse Proxy repository](https://github.com/fatedier/frp)
- [5] [Pinggy Documentation - Usage](https://pinggy.io/docs/usages/)

{{#include ../../banners/hacktricks-training.md}}
