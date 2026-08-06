# local을 internet에 노출

{{#include ../../banners/hacktricks-training.md}}

**이 페이지의 목표는 다른 server에 아무것도 설치하지 않고(필요한 경우 local에만 설치) local raw TCP ports와 local webs(HTTP)를 internet에 노출할 수 있는 대안을 최소한 제안하는 것입니다.**

## **Serveo**

[https://serveo.net/](https://serveo.net/)에서 여러 HTTP 및 port forwarding 기능을 **무료로** 사용할 수 있습니다.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

[https://www.socketxp.com/download](https://www.socketxp.com/download)에서 tcp 및 http를 expose할 수 있습니다:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

[https://ngrok.com/](https://ngrok.com/)을 사용하면 http 및 tcp 포트를 외부에 노출할 수 있습니다:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

[https://telebit.cloud/](https://telebit.cloud/)를 사용하면 http 및 tcp 포트를 외부에 노출할 수 있습니다:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

[https://localxpose.io/](https://localxpose.io/)에서는 여러 HTTP 및 포트 포워딩 기능을 **무료로** 사용할 수 있습니다.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

[https://expose.dev/](https://expose.dev/)를 사용하면 http 및 tcp 포트를 expose할 수 있습니다:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

[https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel)을 사용하면 HTTP를 무료로 expose할 수 있습니다:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Cloudflare의 `cloudflared` CLI는 빠른 데모를 위해 인증 없이 사용할 수 있는 "Quick" tunnels 또는 자체 도메인/호스트 이름에 연결된 named tunnels를 생성할 수 있습니다. HTTP(S) reverse proxy뿐만 아니라 Cloudflare의 edge를 통해 라우팅되는 raw TCP mappings도 지원합니다.<sup>[[1]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
Named tunnels를 사용하면 `tunnel.yml` 내부에 여러 ingress 규칙(HTTP, SSH, RDP 등)을 정의하고, Cloudflare Access를 통해 서비스별 access policy를 적용하며, persistence를 위해 systemd containers로 실행할 수 있습니다. Quick Tunnels는 anonymous이며 ephemeral합니다. 따라서 phishing payload staging이나 webhook tests에 적합하지만, Cloudflare는 uptime을 보장하지 않습니다.<sup>[[1]](#references)</sup>

## Tailscale Funnel / Serve

Tailscale v1.52+에는 통합된 `tailscale serve`(tailnet 내부에서 공유) 및 `tailscale funnel`(더 넓은 인터넷에 publish) workflow가 포함되어 있습니다. 두 command 모두 automatic TLS 및 짧은 `*.ts.net` hostname을 사용해 HTTP(S)를 reverse proxy하거나 raw TCP를 forward할 수 있습니다.<sup>[[3]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
`--bg`를 사용하면 foreground 프로세스를 유지하지 않고도 구성을 지속할 수 있으며, `tailscale funnel status`를 사용하면 public internet에서 접근 가능한 서비스를 감사할 수 있습니다. Funnel은 로컬 노드에서 TLS를 종료하므로 credential prompts, headers 또는 mTLS enforcement를 계속 직접 제어할 수 있습니다.

## Fast Reverse Proxy (frp)

`frp`는 rendezvous server(`frps`)와 client(`frpc`)를 직접 제어하는 self-hosted 옵션입니다. 이미 VPS를 보유하고 deterministic domains/ports를 원하는 red teams에 적합합니다.

<details>
<summary>frps/frpc 구성 예시</summary>
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

최근 릴리스에는 QUIC transport, token/OIDC auth, bandwidth caps, health checks, Go-template 기반 range mappings가 추가되어, 서로 다른 호스트의 implants로 연결되는 여러 listener를 빠르게 구성하는 데 유용합니다.<sup>[[4]](#references)</sup>

## Pinggy (SSH 기반)

Pinggy는 TCP/443을 통한 SSH-accessible tunnels를 제공하므로, HTTPS만 허용하는 captive proxies 뒤에서도 작동합니다. 무료 tier에서는 세션이 60분 동안 유지되며, 빠른 데모나 webhook relays를 위해 스크립트로 구성할 수 있습니다.<sup>[[5]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
유료 tier에서는 custom domains와 더 긴 수명의 tunnels를 요청할 수 있으며, 명령을 loop로 감싸 tunnels를 자동으로 재활용할 수도 있습니다.

## Threat intel 및 OPSEC 참고 사항

Adversaries는 ephemeral tunneling, 특히 인증되지 않은 Cloudflare의 `trycloudflare.com` endpoints를 점점 더 악용하여 Remote Access Trojan payloads를 stage하고 C2 infrastructure를 숨기고 있습니다. Proofpoint는 2024년 2월부터 download stages를 수명이 짧은 TryCloudflare URLs로 지정하여 AsyncRAT, Xworm, VenomRAT, GuLoader 및 Remcos를 전달한 campaigns를 추적했습니다. 이로 인해 기존의 static blocklists는 훨씬 덜 효과적이 되었습니다. Tunnels와 domains를 사전에 rotating하는 것을 고려하되, 사용 중인 tunneler에 대한 외부 DNS lookups라는 명확한 징후도 모니터링하여 blue-team detection 또는 infrastructure blocking attempts를 조기에 파악할 수 있도록 하십시오.<sup>[[2]](#references)</sup>

## References

- [1] [Cloudflare Docs - Create a locally-managed tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [2] [Proofpoint - Threat Actor Abuses Cloudflare Tunnels to Deliver RATs](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
- [3] [Tailscale - Reintroducing Serve and Funnel](https://tailscale.com/blog/reintroducing-serve-funnel)
- [4] [fatedier/frp - Fast Reverse Proxy repository](https://github.com/fatedier/frp)
- [5] [Pinggy Documentation - Usage](https://pinggy.io/docs/usages/)

{{#include ../../banners/hacktricks-training.md}}
