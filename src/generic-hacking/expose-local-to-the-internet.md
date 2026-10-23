# स्थानीय सेवा को इंटरनेट पर उपलब्ध कराना

{{#include ../banners/hacktricks-training.md}}

**इस पृष्ठ का लक्ष्य ऐसे विकल्प सुझाना है जिनसे कम-से-कम स्थानीय raw TCP ports और स्थानीय webs (HTTP) को इंटरनेट पर उपलब्ध कराया जा सके, बिना दूसरे सर्वर पर कुछ भी इंस्टॉल किए (ज़रूरत पड़ने पर केवल स्थानीय मशीन पर इंस्टॉल करके)।**

किसी सार्वजनिक relay के ज़रिए सेवा प्रकाशित करने के बजाय hosts के बीच forwarding के लिए, [Tunneling and Port Forwarding](tunneling-and-port-forwarding.md) देखें।

## **Serveo**

Serveo के दस्तावेज़ में HTTP endpoints के लिए SSH forwarding और private/public TCP forwarding का वर्णन है। अनाम sessions में भी `0` port का अनुरोध करने पर random public TCP port मिलता है, लेकिन उन sessions में समय और connections की सीमाएँ होती हैं; अपनी पसंद का public TCP port माँगने के लिए paid account आवश्यक है।<sup>[[1]](#references)</sup>

```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```

## SocketXP

SocketXP की शुरुआत करने की गाइड में TCP और HTTP tunnels के लिए `socketxp connect tcp://localhost:22` और `socketxp connect http://localhost:8080` कमांड दर्ज हैं; पहले agent को portal token से authenticate किया जाता है।<sup>[[2]](#references)</sup>

```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```

## Ngrok

ngrok का CLI HTTP और TCP tunnels को दस्तावेज़ित करता है। TCP endpoints के लिए account पर reserved TCP address आवश्यक है; free tier के लिए एक मान्य payment method भी आवश्यक है, जिसके बारे में FAQ कहता है कि उससे शुल्क नहीं लिया जाता।<sup>[[3]](#references)[[4]](#references)</sup>

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

LocalXpose की मौजूदा साइट `loclx tunnel http --to 3000` का दस्तावेज़ देती है, HTTP/TLS/TCP/UDP सपोर्ट सूचीबद्ध करती है, और कहती है कि free plan व्यक्तिगत/हल्के व्यावसायिक उपयोग को कवर करता है, जबकि TCP tunneling एक paid-plan सुविधा है।<sup>[[6]](#references)[[7]](#references)</sup>

```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```

## Expose

Expose में HTTP/HTTPS local URLs के लिए `expose share` और TCP ports के लिए केवल PRO में उपलब्ध `expose share-port` command का documentation है।<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```

## Localtunnel

आधिकारिक localtunnel repository, testing के लिए localhost को expose करने का तरीका बताती है और नीचे दिया गया NPX command दस्तावेज़ में शामिल करती है।<sup>[[10]](#references)</sup>

```bash
# Expose web in port 8000
npx localtunnel --port 8000
```

## Cloudflare Tunnel (cloudflared)

Cloudflare के मौजूदा दस्तावेज़ स्थानीय विकास के लिए बिना प्रमाणीकरण वाले "Quick" tunnels दिखाते हैं, और उत्पाद के अवलोकन में समर्थित प्रकाशित प्रोटोकॉल में HTTP, HTTPS, TCP, SSH और RDP शामिल हैं।<sup>[[11]](#references)[[12]](#references)</sup> HTTP(S) के विपरीत, प्रकाशित TCP, SSH और RDP routes को सामान्य client से सीधे एक्सेस नहीं किया जा सकता: Cloudflare के लिए कनेक्ट करने वाले client पर `cloudflared` होना आवश्यक है, इसलिए ये routes raw TCP के लिए इस पेज की client इंस्टॉल न करने की आवश्यकता पूरी नहीं करते।<sup>[[24]](#references)</sup>

स्थानीय रूप से प्रबंधित named tunnel के लिए, Cloudflare `tunnel login`, `create`, `route dns`, और `--config ... run ...` workflow का दस्तावेज़ीकरण करता है।<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```

Named tunnels YAML में कई ingress rules परिभाषित कर सकते हैं; Cloudflare Access policies प्रकाशित applications तक पहुंच नियंत्रित कर सकती हैं, और Cloudflare connectors चलाने के लिए service और Docker deployment के तरीके दस्तावेज़ित करता है। Quick Tunnels anonymous, अस्थायी testing tunnels हैं, जिनकी सीमा 200 concurrent requests है और जो Server-Sent Events (SSE) का समर्थन नहीं करते।<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

Tailscale के मौजूदा CLI में tailnet-only sharing के लिए Serve और public sharing के लिए Funnel का उपयोग होता है। ये commands HTTP/HTTPS reverse-proxy targets और TCP forwarding का समर्थन करती हैं; Funnel का raw TCP mode केवल ports 443, 8443 और 10000 तक सीमित है।<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```

`--bg` का उपयोग करके foreground process को चालू रखे बिना configuration को persist करें, और सार्वजनिक इंटरनेट से पहुँच योग्य services का audit करने के लिए `tailscale funnel status` का उपयोग करें। HTTPS Funnel targets के लिए, Tailscale दस्तावेज़ों के अनुसार request को local service तक forward करने से पहले local node पर TLS termination होता है।<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp` एक self-hosted विकल्प है, जिसमें आप rendezvous server (`frps`) और client (`frpc`) को नियंत्रित करते हैं; इसके documentation में NAT या firewall के पीछे मौजूद local services को निश्चित remote ports/domains के माध्यम से forward करने की जानकारी दी गई है।<sup>[[20]](#references)</sup>

<details>
<summary>frps/frpc configuration का नमूना</summary>

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

वर्तमान project documentation में QUIC transport, token/OIDC authentication, bandwidth limits, health checks और Go-template range mappings शामिल हैं—इनमें से किसी भी विकल्प का उपयोग करने से पहले अपने deployment से मेल खाने वाली release देखें।<sup>[[20]](#references)</sup>

## Pinggy (SSH-based)

Pinggy, port 443 पर SSH reverse forwarding को document करता है, इसलिए यह उन networks में काम कर सकता है जहाँ outbound SSH on port 22 blocked है। इसका free plan 60 minutes के बाद timeout हो जाता है और reconnect करने पर नया URL इस्तेमाल करता है, जबकि Pro में persistent tunnels और custom domains मिलते हैं।<sup>[[21]](#references)[[22]](#references)</sup>

```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```

आप Pro पर custom domains और persistent tunnels का अनुरोध कर सकते हैं।<sup>[[22]](#references)</sup> आप command को loop में लपेटकर temporary tunnels को स्वचालित रूप से recycle कर सकते हैं।

## Threat intel और OPSEC नोट्स

Adversaries ने ephemeral tunneling का दुरुपयोग किया है, जिसमें Cloudflare के unauthenticated `trycloudflare.com` endpoints का इस्तेमाल temporary infrastructure के ज़रिए Remote Access Trojans पहुंचाने के लिए किया गया। Proofpoint ने फरवरी 2024 में पहली बार देखी गई गतिविधि की रिपोर्ट दी, जिसमें Xworm, AsyncRAT, VenomRAT, GuLoader और Remcos शामिल थे। उसने यह भी बताया कि temporary tunnels, static blocklists पर निर्भर defenses के लिए मुश्किलें पैदा करते हैं।<sup>[[23]](#references)</sup> tunnels और domains को सक्रिय रूप से rotate करने पर विचार करें, और इस्तेमाल किए जा रहे tunneler के लिए बाहरी DNS lookups पर नज़र रखें, ताकि blue-team detection या infrastructure blocking की कोशिशों का जल्द पता चल सके।

## References

- [1] [Serveo दस्तावेज़ीकरण](https://serveo.net/docs/)
- [2] [SocketXP दस्तावेज़ीकरण - शुरुआत करें](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [ngrok Agent का Command Line Interface](https://ngrok.com/docs/agent/cli)
- [4] [ngrok के अक्सर पूछे जाने वाले प्रश्न](https://ngrok.com/docs/faq)
- [5] [Telebit.js का पुराना CLI help](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [LocalXpose दस्तावेज़ीकरण](https://localxpose.gitbook.io/docs)
- [8] [Expose - साइटें साझा करना](https://expose.dev/docs/client/sharing)
- [9] [Expose - TCP ports साझा करना](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [localtunnel/localtunnel repository](https://github.com/localtunnel/localtunnel)
- [11] [Cloudflare दस्तावेज़ - Cloudflare Tunnel सेट अप करें](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Cloudflare Tunnel का अवलोकन](https://developers.cloudflare.com/tunnel/)
- [13] [Cloudflare दस्तावेज़ - उपयोगी tunnel commands](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Cloudflare दस्तावेज़ - Routing](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Cloudflare दस्तावेज़ - Configuration file](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Cloudflare Access policies](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Cloudflare दस्तावेज़ - Run parameters](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Tailscale Serve command](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Tailscale Funnel command](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [fatedier/frp - Fast Reverse Proxy repository](https://github.com/fatedier/frp)
- [21] [Pinggy दस्तावेज़ीकरण - उपयोग](https://pinggy.io/docs/usages/)
- [22] [Pinggy - सरल Localhost Tunnels](https://pinggy.io/)
- [23] [Proofpoint - Threat Actor ने RATs पहुंचाने के लिए Cloudflare Tunnels का दुरुपयोग किया](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
- [24] [Cloudflare दस्तावेज़ - Tunnel routing और समर्थित protocols](https://developers.cloudflare.com/tunnel/concepts/routing/)
{{#include ../banners/hacktricks-training.md}}
