# local को internet पर expose करें

{{#include ../../banners/hacktricks-training.md}}

**इस पेज का लक्ष्य ऐसे alternatives प्रस्तुत करना है जो कम से कम local raw TCP ports और local webs (HTTP) को internet पर expose करने की अनुमति दें, बिना दूसरे server में कुछ install किए (यदि आवश्यक हो तो केवल local में)।**

## **Serveo**

Serveo का documentation HTTP endpoints के लिए SSH forwarding और private/public TCP forwarding का वर्णन करता है; non-80/443 public TCP port (जिसमें random port के लिए port 0 भी शामिल है) का अनुरोध करने के लिए registered user आवश्यक है।<sup>[[1]](#references)</sup>
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

SocketXP की getting-started guide में TCP और HTTP tunnels के लिए `socketxp connect tcp://localhost:22` और `socketxp connect http://localhost:8080` दर्ज हैं; agent को पहले portal token से authenticated किया जाता है।<sup>[[2]](#references)</sup>
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

ngrok का CLI HTTP और TCP tunnels को document करता है; इसके FAQ के अनुसार free-tier TCP endpoints के लिए एक valid payment method आवश्यक है और card से कोई charge नहीं लिया जाता।<sup>[[3]](#references)[[4]](#references)</sup>
```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```
## Telebit

legacy Telebit.js CLI help में HTTPS forwarding के लिए `telebit http <port>` और raw TCP के लिए `telebit tcp <local> [remote]` documented हैं; availability deployment और relay पर निर्भर करती है।<sup>[[5]](#references)</sup>
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

LocalXpose की current site `loclx tunnel http --to 3000` को document करती है, HTTP/TLS/TCP/UDP support सूचीबद्ध करती है, और बताती है कि free plan personal/light commercial use को cover करता है, जबकि TCP tunneling paid-plan capability है।<sup>[[6]](#references)[[7]](#references)</sup>
```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```
## Expose

Expose, HTTP/HTTPS local URLs के लिए `expose share` और TCP ports के लिए केवल PRO उपयोगकर्ताओं हेतु `expose share-port` command उपलब्ध कराता है।<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```
## Localtunnel

आधिकारिक localtunnel repository testing के लिए localhost को expose करने का वर्णन करती है और नीचे दिए गए NPX command को document करती है।<sup>[[10]](#references)</sup>
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Cloudflare के वर्तमान docs local development के लिए unauthenticated "Quick" tunnels दिखाते हैं, और product overview supported published protocols में HTTP, HTTPS, TCP, SSH और RDP को शामिल करता है।<sup>[[11]](#references)[[12]](#references)</sup>

Locally managed named tunnel के लिए, Cloudflare `tunnel login`, `create`, `route dns`, और `--config ... run ...` workflow को document करता है।<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```
Named tunnels YAML में कई ingress rules परिभाषित कर सकते हैं; Cloudflare Access policies published applications तक access को नियंत्रित कर सकती हैं, और Cloudflare connectors चलाने के लिए service तथा Docker deployment paths का documentation प्रदान करता है। Quick Tunnels anonymous, temporary testing tunnels हैं, जिनमें 200 concurrent requests की सीमा होती है और Server-Sent Events (SSE) का support नहीं होता।<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

Tailscale का current CLI tailnet-only sharing के लिए Serve और public sharing के लिए Funnel का उपयोग करता है। Commands HTTP/HTTPS reverse-proxy targets और TCP forwarding को support करते हैं; Funnel का raw TCP mode केवल ports 443, 8443 और 10000 तक सीमित है।<sup>[[18]](#references)[[19]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
`--bg` का उपयोग foreground process को चालू रखे बिना configuration को persist करने के लिए करें, और public internet से पहुंच योग्य services का audit करने के लिए `tailscale funnel status` का उपयोग करें। HTTPS Funnel targets के लिए, Tailscale local service को request forward करने से पहले local node पर TLS termination का documentation प्रदान करता है।<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp` एक self-hosted विकल्प है, जिसमें आप rendezvous server (`frps`) और client (`frpc`) को नियंत्रित करते हैं; इसका documentation NAT या firewall के पीछे मौजूद local services को निश्चित remote ports/domains के साथ forward करने को cover करता है।<sup>[[20]](#references)</sup>

<details>
<summary>frps/frpc configuration का उदाहरण</summary>
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

वर्तमान project documentation में QUIC transport, token/OIDC authentication, bandwidth limits, health checks और Go-template range mappings शामिल हैं—इनमें से किसी भी option का उपयोग करने से पहले अपने deployment से मेल खाती release देखें।<sup>[[20]](#references)</sup>

## Pinggy (SSH-based)

Pinggy port 443 पर SSH reverse forwarding को document करता है, इसलिए यह उन networks में काम कर सकता है जहाँ outbound SSH on port 22 blocked है। इसका free plan 60 minutes के बाद timeout हो जाता है और reconnect करने के बाद एक नया URL उपयोग करता है, जबकि Pro persistent tunnels और custom domains जोड़ता है।<sup>[[21]](#references)[[22]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```
आप Pro पर custom domains और persistent tunnels का अनुरोध कर सकते हैं।<sup>[[22]](#references)</sup> आप command को loop में wrap करके temporary tunnels को स्वचालित रूप से recycle कर सकते हैं।

## Threat intel & OPSEC notes

Adversaries ने ephemeral tunneling का दुरुपयोग किया है, जिसमें Cloudflare के unauthenticated `trycloudflare.com` endpoints का उपयोग temporary infrastructure के माध्यम से Remote Access Trojans वितरित करने के लिए किया गया। Proofpoint ने फरवरी 2024 में पहली बार देखी गई activity की report की, जिसमें Xworm, AsyncRAT, VenomRAT, GuLoader और Remcos शामिल थे, और बताया कि temporary tunnels static blocklists पर निर्भर defenses को जटिल बना देते हैं।<sup>[[23]](#references)</sup> Tunnels और domains को proactive रूप से rotate करने पर विचार करें, और आपके द्वारा उपयोग किए जा रहे tunneler को होने वाले स्पष्ट external DNS lookups की निगरानी करें, ताकि blue-team detection या infrastructure blocking attempts का शुरुआती चरण में पता लगाया जा सके।

## References

- [1] [Serveo Documentation](https://serveo.net/docs/)
- [2] [SocketXP Documentation - Getting Started](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [ngrok Agent Command Line Interface](https://ngrok.com/docs/agent/cli)
- [4] [ngrok FAQ](https://ngrok.com/docs/faq)
- [5] [Telebit.js legacy CLI help](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [LocalXpose Documentation](https://localxpose.gitbook.io/docs)
- [8] [Expose - Sharing sites](https://expose.dev/docs/client/sharing)
- [9] [Expose - Sharing TCP ports](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [localtunnel/localtunnel repository](https://github.com/localtunnel/localtunnel)
- [11] [Cloudflare Docs - Set up Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Cloudflare Tunnel overview](https://developers.cloudflare.com/tunnel/)
- [13] [Cloudflare Docs - Useful tunnel commands](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Cloudflare Docs - Routing](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Cloudflare Docs - Configuration file](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Cloudflare Access policies](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Cloudflare Docs - Run parameters](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Tailscale Serve command](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Tailscale Funnel command](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [fatedier/frp - Fast Reverse Proxy repository](https://github.com/fatedier/frp)
- [21] [Pinggy Documentation - Usage](https://pinggy.io/docs/usages/)
- [22] [Pinggy - Simple Localhost Tunnels](https://pinggy.io/)
- [23] [Proofpoint - Threat Actor Abuses Cloudflare Tunnels to Deliver RATs](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
{{#include ../../banners/hacktricks-training.md}}
