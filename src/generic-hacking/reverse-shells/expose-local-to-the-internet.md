# 로컬을 인터넷에 노출하기

{{#include ../../banners/hacktricks-training.md}}

**이 페이지의 목표는 적어도 로컬 raw TCP ports와 로컬 웹(HTTP)을 다른 서버에 아무것도 설치할 필요 없이(필요하다면 로컬에만 설치) 인터넷에 노출할 수 있는 대안을 제시하는 것입니다.**

## **Serveo**

From [https://serveo.net/](https://serveo.net/), https://serveo.net/에서는 여러 http 및 port forwarding 기능을 **무료로** 제공합니다.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

[https://www.socketxp.com/download](https://www.socketxp.com/download)에서 tcp와 http를 노출할 수 있습니다:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

[https://ngrok.com/](https://ngrok.com/)을 통해 http 및 tcp 포트를 외부에 노출할 수 있습니다:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

[https://telebit.cloud/](https://telebit.cloud/)에서 http 및 tcp 포트를 노출할 수 있습니다:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

[https://localxpose.io/](https://localxpose.io/)에서 여러 http 및 포트 포워딩 기능을 **무료로** 제공합니다.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

[https://expose.dev/](https://expose.dev/)는 http 및 tcp 포트를 노출할 수 있습니다:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

[https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel)에서 http를 무료로 노출할 수 있습니다:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Cloudflare의 `cloudflared` CLI는 빠른 데모를 위한 인증 없는 "Quick" 터널이나 본인의 도메인/호스트명에 바인딩된 명명된 터널을 생성할 수 있습니다. HTTP(S) reverse proxies와 Cloudflare의 edge를 통해 라우팅되는 raw TCP mappings도 지원합니다.
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
Named tunnels을 사용하면 `tunnel.yml` 안에 여러 개의 ingress 규칙(HTTP, SSH, RDP 등)을 정의할 수 있고, Cloudflare Access를 통해 서비스별 접근 정책을 지원하며 영속성을 위해 systemd 컨테이너로 실행할 수 있습니다. Quick Tunnels은 익명이고 일시적이어서 phishing payload staging이나 webhook 테스트에 적합하지만, Cloudflare는 가동 시간을 보장하지 않습니다.

## Tailscale Funnel / Serve

Tailscale v1.52+는 통합된 `tailscale serve`(tailnet 내부에서 공유)와 `tailscale funnel`(인터넷에 공개) 워크플로우를 제공합니다. 두 명령 모두 자동 TLS와 짧은 `*.ts.net` 호스트명을 사용해 HTTP(S)를 reverse proxy하거나 raw TCP를 forward할 수 있습니다.
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
`--bg`를 사용하면 포그라운드 프로세스를 유지하지 않고도 구성을 지속할 수 있으며, `tailscale funnel status`로 공개 인터넷에서 접근 가능한 서비스를 감사할 수 있습니다. Funnel은 로컬 노드에서 TLS를 종료하므로 인증 정보 입력 요청, 헤더, 또는 mTLS 적용은 여전히 귀하의 통제 하에 남아 있을 수 있습니다.

## Fast Reverse Proxy (frp)

`frp`는 rendezvous 서버(`frps`)와 클라이언트(`frpc`)를 직접 제어하는 self-hosted 옵션입니다. 이미 VPS를 보유하고 있고 예측 가능한 도메인/포트를 원하는 red teams에 적합합니다.

<details>
<summary>샘플 frps/frpc 구성</summary>
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

최근 릴리스는 QUIC transport, token/OIDC auth, bandwidth caps, health checks, 및 Go-template-based range mappings를 추가했습니다 — 서로 다른 호스트의 implants로 매핑되는 여러 리스너를 신속히 띄우는 데 유용합니다.

## Pinggy (SSH-based)

Pinggy는 TCP/443을 통해 SSH-accessible 터널을 제공하므로 HTTPS만 허용하는 captive proxies 뒤에서도 작동합니다. 세션은 무료 티어에서 60분 동안 지속되며, 빠른 데모나 webhook relays용으로 스크립트화할 수 있습니다.
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
유료 티어에서는 커스텀 도메인과 더 오래 유지되는 터널을 요청할 수 있으며, 명령을 루프로 감싸 터널을 자동으로 재활용할 수도 있습니다.

## 위협 인텔 및 OPSEC 노트

공격자들은 점점 더 일시적 터널링(ephemeral tunneling), 특히 Cloudflare의 인증이 필요 없는 `trycloudflare.com` 엔드포인트를 악용해 Remote Access Trojan 페이로드를 배치하고 C2 인프라를 은닉하고 있습니다. Proofpoint는 2024년 2월 이후 다운로드 단계를 단기 TryCloudflare URL로 지정해 AsyncRAT, Xworm, VenomRAT, GuLoader, Remcos를 유포한 캠페인을 추적했으며, 이로 인해 기존의 정적 차단 목록(static blocklists)은 훨씬 덜 효과적이게 되었습니다. 터널과 도메인을 사전적으로 주기 교체하는 것을 고려하되, 사용 중인 tunneler로 향하는 외부 DNS 조회 같은 징후를 모니터링하여 blue-team의 탐지나 인프라 차단 시도를 조기에 포착하세요.

## 참고자료

- [Cloudflare Docs - Create a locally-managed tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [Proofpoint - Threat Actor Abuses Cloudflare Tunnels to Deliver RATs](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)

{{#include ../../banners/hacktricks-training.md}}
