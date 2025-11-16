# local को इंटरनेट पर एक्सपोज़ करें

{{#include ../../banners/hacktricks-training.md}}

**इस पेज का उद्देश्य ऐसे विकल्प प्रस्तावित करना है जो कम से कम local के raw TCP पोर्ट्स और local वेब्स (HTTP) को इंटरनेट पर एक्सपोज़ करने की अनुमति दें, दूसरे server पर कुछ भी install किए बिना (यदि आवश्यक हो तो केवल local में)।**

## **Serveo**

यह [https://serveo.net/](https://serveo.net/) कई http और port forwarding सुविधाएँ **मुफ्त में** प्रदान करता है।
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

यह [https://www.socketxp.com/download](https://www.socketxp.com/download) से tcp और http एक्सपोज़ करने की अनुमति देता है:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

[https://ngrok.com/](https://ngrok.com/) से यह http और tcp पोर्ट्स को एक्सपोज़ करने की अनुमति देता है:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

[https://telebit.cloud/](https://telebit.cloud/) से यह http और tcp पोर्ट्स को expose करने की अनुमति देता है:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

[https://localxpose.io/](https://localxpose.io/) से, यह कई http और port forwarding विशेषताएँ **मुफ्त में** उपलब्ध कराता है।
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

[https://expose.dev/](https://expose.dev/) से यह http और tcp पोर्ट्स को expose करने की अनुमति देता है:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

[https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) से यह http को मुफ्त में एक्सपोज़ करने की अनुमति देता है:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Cloudflare का `cloudflared` CLI तेज़ डेमो के लिए बिना प्रमाणीकरण वाले "Quick" tunnels बना सकता है या आपके अपने domain/hostnames से बंधे named tunnels। यह HTTP(S) reverse proxies के साथ-साथ raw TCP mappings का भी समर्थन करता है, जो Cloudflare के edge के माध्यम से मार्गित होते हैं।
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
Named tunnels आपको `tunnel.yml` के अंदर multiple ingress rules (HTTP, SSH, RDP, आदि) define करने देते हैं, per-service access policies को Cloudflare Access के माध्यम से support करते हैं, और persistence के लिए systemd containers के रूप में run कर सकते हैं। Quick Tunnels anonymous और ephemeral होते हैं—phishing payload staging या webhook tests के लिए बढ़िया, लेकिन Cloudflare uptime की गारंटी नहीं देता।

## Tailscale Funnel / Serve

Tailscale v1.52+ unified `tailscale serve` (tailnet के अंदर साझा करना) और `tailscale funnel` (विस्तृत इंटरनेट पर publish करना) workflows के साथ आता है। दोनों commands HTTP(S) को reverse proxy कर सकते हैं या automatic TLS और short `*.ts.net` hostnames के साथ raw TCP को forward कर सकते हैं।
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
कॉन्फ़िगरेशन स्थायी करने के लिए `--bg` का उपयोग करें बिना किसी foreground process को चलाए रखने के, और यह ऑडिट करने के लिए कि कौन सी सेवाएँ सार्वजनिक इंटरनेट से पहुँच योग्य हैं, `tailscale funnel status` चलाएँ। क्योंकि Funnel लोकल नोड पर TLS को terminate करता है, कोई भी credential prompts, headers, या mTLS enforcement आपके नियंत्रण में रह सकती/रह सकते हैं।

## Fast Reverse Proxy (frp)

`frp` एक self-hosted विकल्प है जहाँ आप rendezvous server (`frps`) और क्लाइंट (`frpc`) को नियंत्रित करते हैं। यह उन red teams के लिए बेहतरीन है जिनके पास पहले से एक VPS है और जो deterministic domains/ports चाहते हैं।

<details>
<summary>frps/frpc कॉन्फ़िगरेशन का उदाहरण</summary>
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

हालिया रिलीज़ में QUIC transport, token/OIDC auth, bandwidth caps, health checks, और Go-template-based range mappings जोड़े गए हैं — ये जल्दी से कई listeners खड़े करने में उपयोगी हैं जो अलग-अलग hosts पर मौजूद implants की ओर मैप होते हैं।

## Pinggy (SSH-based)

Pinggy SSH-accessible tunnels को TCP/443 पर प्रदान करता है, इसलिए यह उन captive proxies के पीछे भी काम करता है जो केवल HTTPS की अनुमति देते हैं। Sessions free tier पर 60 मिनट तक चलते हैं और इन्हें quick demos या webhook relays के लिए scripted किया जा सकता है।
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
आप पेड टियर पर custom domains और longer-lived tunnels का अनुरोध कर सकते हैं, या कमांड को लूप में लपेटकर tunnels को स्वचालित रूप से रीसायकल कर सकते हैं।

## Threat intel & OPSEC notes

हमलावर बढ़ती संख्या में ephemeral tunneling का दुरुपयोग कर रहे हैं (विशेषकर Cloudflare के unauthenticated `trycloudflare.com` endpoints) ताकि Remote Access Trojan payloads को स्टेज किया जा सके और C2 infrastructure छिपाया जा सके। Proofpoint ने फ़रवरी 2024 से ऐसी अभियानों को ट्रैक किया है जिन्होंने AsyncRAT, Xworm, VenomRAT, GuLoader, और Remcos को short-lived TryCloudflare URLs की ओर download stages निर्देशित करके वितरित किया, जिससे पारंपरिक static blocklists बहुत कम प्रभावी हो गए। tunnels और domains को proactively rotate करने पर विचार करें, और साथ ही उस tunneler के लिए संकेतक-स्वरूप external DNS lookups की निगरानी भी करें जिसे आप उपयोग कर रहे हैं, ताकि आप blue-team detection या infrastructure blocking प्रयासों का जल्दी पता लगा सकें।

## References

- [Cloudflare Docs - Create a locally-managed tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [Proofpoint - Threat Actor Abuses Cloudflare Tunnels to Deliver RATs](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)

{{#include ../../banners/hacktricks-training.md}}
