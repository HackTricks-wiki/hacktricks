# 로컬을 인터넷에 노출

{{#include ../../banners/hacktricks-training.md}}

**이 페이지의 목표는 다른 서버에 아무것도 설치하지 않고(필요한 경우 로컬에만 설치) 로컬 raw TCP 포트와 로컬 웹(HTTP)을 인터넷에 노출할 수 있는 대안을 최소한 제안하는 것입니다.**

## **Serveo**

Serveo의 문서에서는 HTTP 엔드포인트와 private/public TCP forwarding을 위한 SSH forwarding을 설명합니다. 80/443이 아닌 public TCP 포트(임의의 포트를 위한 포트 0 포함)를 요청하려면 registered user가 필요합니다.<sup>[[1]](#references)</sup>
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

SocketXP의 getting-started guide에는 TCP 및 HTTP 터널을 위한 `socketxp connect tcp://localhost:22` 및 `socketxp connect http://localhost:8080`이 문서화되어 있으며, 먼저 agent가 portal token으로 인증됩니다.<sup>[[2]](#references)</sup>
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

ngrok의 CLI는 HTTP 및 TCP 터널을 문서화하며, FAQ에 따르면 무료 요금제의 TCP 엔드포인트에는 유효한 결제 수단이 필요하지만 카드에는 요금이 청구되지 않습니다.<sup>[[3]](#references)[[4]](#references)</sup>
```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```
## Telebit

legacy Telebit.js CLI help 문서에는 HTTPS 포워딩에 `telebit http <port>`, raw TCP에 `telebit tcp <local> [remote]`를 사용한다고 나와 있습니다. 사용 가능 여부는 deployment 및 relay에 따라 달라집니다.<sup>[[5]](#references)</sup>
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

LocalXpose의 현재 사이트에는 `loclx tunnel http --to 3000`이 문서화되어 있으며, HTTP/TLS/TCP/UDP 지원을 나열하고 있습니다. 또한 무료 플랜은 개인적/경량 상업적 사용을 지원하고 TCP tunneling은 유료 플랜 기능이라고 설명합니다.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```
Expose는 HTTP/HTTPS 로컬 URL을 위한 `expose share`와 TCP 포트를 위한 PRO 전용 `expose share-port` 명령을 문서화합니다.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```
## Localtunnel

공식 localtunnel repository는 테스트를 위해 localhost를 외부에 노출하는 방법을 설명하며 아래의 NPX 명령을 문서화합니다.<sup>[[10]](#references)</sup>
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Cloudflare의 현재 문서에는 로컬 개발을 위한 인증되지 않은 "Quick" tunnel이 안내되어 있으며, 제품 개요에는 지원되는 게시 프로토콜로 HTTP, HTTPS, TCP, SSH, RDP가 나열되어 있습니다.<sup>[[11]](#references)[[12]](#references)</sup>

로컬에서 관리하는 named tunnel의 경우, Cloudflare는 `tunnel login`, `create`, `route dns`, `--config ... run ...` 워크플로를 문서화하고 있습니다.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```
Named tunnels은 YAML에서 여러 ingress 규칙을 정의할 수 있으며, Cloudflare Access policies는 published applications에 대한 access를 제어할 수 있습니다. 또한 Cloudflare는 connector를 실행하기 위한 service 및 Docker deployment 경로를 문서화하고 있습니다. Quick Tunnels는 200개의 동시 요청 제한이 있고 Server-Sent Events (SSE)를 지원하지 않는 anonymous temporary testing tunnels입니다.<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

Tailscale의 현재 CLI는 tailnet 내부 공유에 Serve를 사용하고 public sharing에 Funnel을 사용합니다. 이 commands는 HTTP/HTTPS reverse-proxy targets 및 TCP forwarding을 지원하며, Funnel의 raw TCP mode는 443, 8443, 10000 ports로 제한됩니다.<sup>[[18]](#references)[[19]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
`--bg`를 사용하면 foreground process를 유지하지 않고 configuration을 persist할 수 있으며, `tailscale funnel status`를 사용하면 public internet에서 접근 가능한 service를 audit할 수 있습니다. HTTPS Funnel target의 경우, Tailscale 문서에서는 request를 local service로 forwarding하기 전에 local node에서 TLS termination이 수행된다고 설명합니다.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp`는 rendezvous server(`frps`)와 client(`frpc`)를 직접 control하는 self-hosted option입니다. 해당 documentation에서는 NAT 또는 firewall 뒤의 local service를 deterministic remote port/domain으로 forwarding하는 방법을 다룹니다.<sup>[[20]](#references)</sup>

<details>
<summary>frps/frpc configuration sample</summary>
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

현재 프로젝트 문서에는 QUIC transport, token/OIDC authentication, bandwidth limits, health checks, Go-template range mappings이 포함되어 있으므로, 이러한 옵션을 사용하기 전에 배포 환경에 맞는 release를 확인하세요.<sup>[[20]](#references)</sup>

## Pinggy (SSH 기반)

Pinggy는 port 443을 통한 SSH reverse forwarding을 문서화하고 있으므로, outbound SSH가 port 22에서 차단된 네트워크에서도 작동할 수 있습니다. 무료 플랜은 60분 후 timeout되며 reconnect 시 새 URL을 사용합니다. Pro는 persistent tunnels와 custom domains를 추가로 제공합니다.<sup>[[21]](#references)[[22]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```
Pro에서는 custom domain과 persistent tunnel을 요청할 수 있습니다.<sup>[[22]](#references)</sup> 명령을 loop로 감싸 temporary tunnel을 자동으로 재활용할 수 있습니다.

## Threat intel & OPSEC notes

Adversaries는 임시 인프라를 통해 Remote Access Trojans를 전달하기 위해 Cloudflare의 인증되지 않은 `trycloudflare.com` endpoint를 포함한 ephemeral tunneling을 악용해 왔습니다. Proofpoint는 2024년 2월 처음 관찰된 활동을 보고했으며, Xworm, AsyncRAT, VenomRAT, GuLoader, Remcos가 사용되었다고 밝혔습니다. 또한 temporary tunnel은 static blocklist에 의존하는 방어를 어렵게 만든다고 지적했습니다.<sup>[[23]](#references)</sup> tunnel과 domain을 선제적으로 교체하고, 사용 중인 tunneler에 대한 외부 DNS lookup이라는 명확한 징후를 모니터링하여 blue team의 탐지 또는 infrastructure 차단 시도를 조기에 파악할 수 있도록 하십시오.

## References

- [1] [Serveo Documentation](https://serveo.net/docs/)
- [2] [SocketXP Documentation - 시작하기](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [ngrok Agent Command Line Interface](https://ngrok.com/docs/agent/cli)
- [4] [ngrok FAQ](https://ngrok.com/docs/faq)
- [5] [Telebit.js legacy CLI 도움말](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [LocalXpose Documentation](https://localxpose.gitbook.io/docs)
- [8] [Expose - Sharing sites](https://expose.dev/docs/client/sharing)
- [9] [Expose - TCP port 공유](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [localtunnel/localtunnel repository](https://github.com/localtunnel/localtunnel)
- [11] [Cloudflare Docs - Cloudflare Tunnel 설정](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Cloudflare Tunnel 개요](https://developers.cloudflare.com/tunnel/)
- [13] [Cloudflare Docs - 유용한 tunnel 명령](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Cloudflare Docs - Routing](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Cloudflare Docs - Configuration file](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Cloudflare Access policies](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Cloudflare Docs - Run parameters](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Tailscale Serve command](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Tailscale Funnel command](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [fatedier/frp - Fast Reverse Proxy repository](https://github.com/fatedier/frp)
- [21] [Pinggy Documentation - Usage](https://pinggy.io/docs/usages/)
- [22] [Pinggy - Simple Localhost Tunnels](https://pinggy.io/)
- [23] [Proofpoint - Threat Actor가 RAT를 전달하기 위해 Cloudflare Tunnel을 악용](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
{{#include ../../banners/hacktricks-training.md}}
