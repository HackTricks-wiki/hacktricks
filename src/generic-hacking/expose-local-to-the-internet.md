# स्थानीय को इंटरनेट पर उपलब्ध कराना

{{#include ../banners/hacktricks-training.md}}

**इस पेज का उद्देश्य ऐसे विकल्प सुझाना है जिनसे कम-से-कम स्थानीय raw TCP ports और स्थानीय वेब सेवाओं (HTTP) को इंटरनेट पर उपलब्ध कराया जा सके—बिना दूसरे सर्वर पर कुछ भी इंस्टॉल किए (ज़रूरत पड़ने पर केवल स्थानीय मशीन पर)।**

## **Serveo**

Serveo के documentation में HTTP endpoints के लिए SSH forwarding और private/public TCP forwarding का वर्णन है; non-80/443 public TCP port (जिसमें random port के लिए port 0 भी शामिल है) का अनुरोध करने के लिए registered user होना आवश्यक है।<sup>[[1]](#references)</sup>

```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```

## SocketXP

SocketXP की शुरुआती गाइड TCP और HTTP tunnels के लिए `socketxp connect tcp://localhost:22` और `socketxp connect http://localhost:8080` कमांड दर्ज करती है; पहले agent को portal token से authenticate किया जाता है।<sup>[[2]](#references)</sup>

```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```

## Ngrok

ngrok का CLI HTTP और TCP tunnels को document करता है; इसकी FAQ के अनुसार free-tier TCP endpoints के लिए valid payment method आवश्यक है और card से शुल्क नहीं लिया जाता।<sup>[[3]](#references)[[4]](#references)</sup>

```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```

## Telebit

पुराने Telebit.js CLI help में HTTPS forwarding के लिए `telebit http <port>` और raw TCP के लिए `telebit tcp <local> [remote]` दर्ज हैं; उपलब्धता deployment और relay पर निर्भर करती है।<sup>[[5]](#references)</sup>

```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```

## LocalXpose

LocalXpose की वर्तमान साइट `loclx tunnel http --to 3000` को दस्तावेज़ित करती है, HTTP/TLS/TCP/UDP सपोर्ट सूचीबद्ध करती है, और बताती है कि मुफ़्त योजना में व्यक्तिगत/हल्के व्यावसायिक उपयोग शामिल हैं, जबकि TCP tunneling सशुल्क योजना की सुविधा है।<sup>[[6]](#references)[[7]](#references)</sup>

```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```

## Expose

HTTP/HTTPS local URLs के लिए `expose share` और TCP ports के लिए केवल PRO में उपलब्ध `expose share-port` command दस्तावेज़ करता है।<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```

## Localtunnel

आधिकारिक localtunnel repository, testing के लिए localhost को expose करने का वर्णन करता है और नीचे दिए गए NPX command का documentation देता है।<sup>[[10]](#references)</sup>

```bash
# Expose web in port 8000
npx localtunnel --port 8000
```

## Cloudflare Tunnel (cloudflared)

Cloudflare के मौजूदा दस्तावेज़ों में local development के लिए बिना authentication वाले "Quick" tunnels दिखाए गए हैं, और product overview में समर्थित published protocols में HTTP, HTTPS, TCP, SSH और RDP शामिल हैं।<sup>[[11]](#references)[[12]](#references)</sup>

Locally managed named tunnel के लिए, Cloudflare `tunnel login`, `create`, `route dns` और `--config ... run ...` workflow का दस्तावेज़ीकरण करता है।<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```

Named tunnels YAML में कई ingress rules परिभाषित कर सकते हैं; Cloudflare Access policies प्रकाशित applications तक पहुंच नियंत्रित कर सकती हैं, और Cloudflare connectors चलाने के लिए service और Docker deployment के तरीके दस्तावेज़ करता है। Quick Tunnels anonymous, अस्थायी testing tunnels हैं, जिनकी सीमा 200 concurrent requests है और जिनमें Server-Sent Events (SSE) का समर्थन नहीं है।<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

Tailscale का मौजूदा CLI, tailnet-only sharing के लिए Serve और public sharing के लिए Funnel का उपयोग करता है। ये commands HTTP/HTTPS reverse-proxy targets और TCP forwarding का समर्थन करती हैं; Funnel का raw TCP mode केवल 443, 8443 और 10000 ports तक सीमित है।<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```

`--bg` का उपयोग करके foreground process चलाए बिना कॉन्फ़िगरेशन को persist करें, और यह ऑडिट करने के लिए `tailscale funnel status` का उपयोग करें कि कौन-सी services सार्वजनिक इंटरनेट से reachable हैं। HTTPS Funnel targets के लिए, Tailscale दस्तावेज़ में बताया गया है कि request को local service पर forward करने से पहले local node पर TLS termination होता है।<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp` एक self-hosted विकल्प है, जिसमें rendezvous server (`frps`) और client (`frpc`) का नियंत्रण आपके पास होता है; इसके documentation में NAT या firewall के पीछे local services को निश्चित remote ports/domains के ज़रिए forward करने का तरीका बताया गया है।<sup>[[20]](#references)</sup>

<details>
<summary>frps/frpc कॉन्फ़िगरेशन का उदाहरण</summary>

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

मौजूदा प्रोजेक्ट दस्तावेज़ में QUIC transport, token/OIDC authentication, bandwidth limits, health checks और Go-template range mappings शामिल हैं—इनमें से किसी भी विकल्प का उपयोग करने से पहले अपनी deployment से मेल खाने वाली release देखें।<sup>[[20]](#references)</sup>

## Pinggy (SSH-based)

Pinggy, port 443 पर SSH reverse forwarding का दस्तावेज़ देता है, इसलिए यह उन नेटवर्कों में काम कर सकता है जहाँ outbound SSH on port 22 blocked है। इसका free plan 60 मिनट बाद timeout हो जाता है और reconnect करने पर नया URL इस्तेमाल करता है, जबकि Pro में persistent tunnels और custom domains मिलते हैं।<sup>[[21]](#references)[[22]](#references)</sup>

```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```

आप Pro पर custom domains और persistent tunnels का अनुरोध कर सकते हैं।<sup>[[22]](#references)</sup> Command को loop में लपेटकर temporary tunnels को अपने-आप recycle कर सकते हैं।

## Threat intel और OPSEC नोट्स

Adversaries ने ephemeral tunneling का दुरुपयोग किया है। इसमें Cloudflare के unauthenticated `trycloudflare.com` endpoints के ज़रिए temporary infrastructure से Remote Access Trojans पहुँचाना भी शामिल है। Proofpoint ने फरवरी 2024 में पहली बार देखी गई गतिविधि की रिपोर्ट दी, जिसमें Xworm, AsyncRAT, VenomRAT, GuLoader और Remcos शामिल थे। उसने यह भी बताया कि temporary tunnels उन defenses के लिए मुश्किलें खड़ी करते हैं जो static blocklists पर निर्भर करती हैं।<sup>[[23]](#references)</sup> Tunnels और domains को पहले से बदलते रहने पर विचार करें। साथ ही, अपने इस्तेमाल किए जा रहे tunneler के लिए होने वाले विशिष्ट external DNS lookups पर नज़र रखें, ताकि blue-team detection या infrastructure को block करने की कोशिशों का जल्द पता चल सके।

## References

- [1] [Serveo दस्तावेज़](https://serveo.net/docs/)
- [2] [SocketXP दस्तावेज़ - शुरुआत करना](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [ngrok Agent Command Line Interface](https://ngrok.com/docs/agent/cli)
- [4] [ngrok FAQ](https://ngrok.com/docs/faq)
- [5] [Telebit.js legacy CLI सहायता](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [LocalXpose दस्तावेज़](https://localxpose.gitbook.io/docs)
- [8] [Expose - साइटें साझा करना](https://expose.dev/docs/client/sharing)
- [9] [Expose - TCP ports साझा करना](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [localtunnel/localtunnel repository](https://github.com/localtunnel/localtunnel)
- [11] [Cloudflare Docs - Cloudflare Tunnel सेट अप करना](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Cloudflare Tunnel का अवलोकन](https://developers.cloudflare.com/tunnel/)
- [13] [Cloudflare Docs - उपयोगी tunnel commands](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Cloudflare Docs - Routing](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Cloudflare Docs - Configuration file](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Cloudflare Access policies](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Cloudflare Docs - Run parameters](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Tailscale Serve command](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Tailscale Funnel command](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [fatedier/frp - Fast Reverse Proxy repository](https://github.com/fatedier/frp)
- [21] [Pinggy दस्तावेज़ - उपयोग](https://pinggy.io/docs/usages/)
- [22] [Pinggy - सरल Localhost Tunnels](https://pinggy.io/)
- [23] [Proofpoint - Threat Actor ने RATs पहुँचाने के लिए Cloudflare Tunnels का दुरुपयोग किया](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
{{#include ../banners/hacktricks-training.md}}
