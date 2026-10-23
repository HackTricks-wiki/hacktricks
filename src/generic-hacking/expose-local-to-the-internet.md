# 인터넷에 로컬 서비스 노출하기

{{#include ../banners/hacktricks-training.md}}

**이 페이지의 목표는 다른 서버에 아무것도 설치하지 않고(필요한 경우 로컬에만 설치) 로컬 raw TCP 포트와 로컬 웹(HTTP)을 인터넷에 노출할 수 있는 대안을 제시하는 것입니다.**

공개 릴레이를 통해 서비스를 공개하는 대신 호스트 간에 포워딩하려면 [Tunneling and Port Forwarding](tunneling-and-port-forwarding.md)을 참조하세요.

## **Serveo**

Serveo 문서에는 HTTP 엔드포인트를 위한 SSH 포워딩과 비공개/공개 TCP 포워딩이 설명되어 있습니다. 포트 `0`을 요청하면 익명 세션에서도 임의의 공개 TCP 포트를 할당받을 수 있지만, 해당 세션에는 짧은 시간 및 연결 제한이 적용됩니다. 원하는 공개 TCP 포트를 지정하려면 유료 계정이 필요합니다.<sup>[[1]](#references)</sup>

```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```

## SocketXP

SocketXP의 시작 가이드에는 TCP 및 HTTP 터널용 `socketxp connect tcp://localhost:22` 및 `socketxp connect http://localhost:8080` 명령이 설명되어 있습니다. 에이전트는 먼저 포털 토큰으로 인증됩니다.<sup>[[2]](#references)</sup>

```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```

## Ngrok

ngrok의 CLI는 HTTP 및 TCP 터널을 문서화합니다. TCP endpoint를 사용하려면 계정에 예약된 TCP 주소가 필요합니다. 무료 요금제에서도 유효한 결제 수단이 필요하지만, FAQ에 따르면 요금은 청구되지 않습니다.<sup>[[3]](#references)[[4]](#references)</sup>

```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```

## Telebit

기존 Telebit.js CLI 도움말에는 HTTPS 포워딩을 위한 `telebit http <port>`와 raw TCP를 위한 `telebit tcp <local> [remote]`가 문서화되어 있습니다. 사용 가능 여부는 배포 환경과 relay에 따라 달라집니다.<sup>[[5]](#references)</sup>

```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```

## LocalXpose

LocalXpose의 현재 사이트에는 `loclx tunnel http --to 3000` 명령이 안내되어 있으며, HTTP/TLS/TCP/UDP를 지원한다고 나와 있습니다. 또한 무료 플랜은 개인 및 가벼운 상업적 용도를 지원하고, TCP 터널링은 유료 플랜에서 제공되는 기능이라고 설명합니다.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```

## Expose

Expose는 HTTP/HTTPS 로컬 URL을 위한 `expose share`와 TCP 포트를 위한 PRO 전용 `expose share-port` 명령을 문서화합니다.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```

## Localtunnel

공식 localtunnel 저장소에서는 테스트를 위해 localhost를 외부에 공개하는 방법을 설명하고, 아래의 NPX 명령을 안내합니다.<sup>[[10]](#references)</sup>

```bash
# Expose web in port 8000
npx localtunnel --port 8000
```

## Cloudflare Tunnel (cloudflared)

Cloudflare의 최신 문서에는 로컬 개발을 위한 인증되지 않은 "Quick" 터널이 안내되어 있으며, 제품 개요에는 지원되는 게시 프로토콜로 HTTP, HTTPS, TCP, SSH, RDP가 나열되어 있습니다.<sup>[[11]](#references)[[12]](#references)</sup> HTTP(S)와 달리 게시된 TCP, SSH, RDP 경로는 기본 클라이언트로 직접 접속할 수 없습니다. Cloudflare는 접속 클라이언트에 `cloudflared`를 요구하므로, 이러한 경로는 raw TCP에 대해 이 페이지에서 요구하는 클라이언트 설치 불필요 조건을 충족하지 않습니다.<sup>[[24]](#references)</sup>

로컬에서 관리하는 이름 있는 터널의 경우, Cloudflare 문서에는 `tunnel login`, `create`, `route dns`, `--config ... run ...` 워크플로가 안내되어 있습니다.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```

Named tunnel은 YAML에서 여러 ingress 규칙을 정의할 수 있습니다. Cloudflare Access 정책으로 게시된 애플리케이션에 대한 액세스를 제어할 수 있으며, Cloudflare는 connector를 실행하는 서비스 및 Docker 배포 방법을 문서화하고 있습니다. Quick Tunnel은 익명으로 사용할 수 있는 임시 테스트 tunnel이며, 동시 요청은 최대 200개까지 지원하고 Server-Sent Events (SSE)는 지원하지 않습니다.<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

Tailscale의 현재 CLI는 tailnet 전용 공유에 Serve를, 공개 공유에 Funnel을 사용합니다. 명령어는 HTTP/HTTPS reverse-proxy 대상과 TCP forwarding을 지원합니다. Funnel의 raw TCP 모드는 포트 443, 8443, 10000으로 제한됩니다.<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```

`--bg`를 사용하면 foreground process를 유지하지 않고 구성을 지속적으로 적용할 수 있으며, `tailscale funnel status`를 사용하면 공용 인터넷에서 접근할 수 있는 서비스를 점검할 수 있습니다. HTTPS Funnel 대상의 경우, Tailscale 문서에 따르면 요청을 로컬 서비스로 전달하기 전에 로컬 노드에서 TLS를 종료합니다.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp`는 rendezvous server(`frps`)와 client(`frpc`)를 직접 제어하는 self-hosted 옵션입니다. 문서에서는 NAT 또는 방화벽 뒤에 있는 로컬 서비스를 고정된 원격 포트/도메인으로 포워딩하는 방법을 다룹니다.<sup>[[20]](#references)</sup>

<details>
<summary>frps/frpc 구성 예시</summary>

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

현재 프로젝트 문서에는 QUIC transport, token/OIDC 인증, 대역폭 제한, health check, Go-template range 매핑이 포함되어 있습니다. 이러한 옵션을 사용하기 전에 배포 환경에 맞는 버전의 문서를 확인하세요.<sup>[[20]](#references)</sup>

## Pinggy (SSH 기반)

Pinggy는 포트 443을 통한 SSH reverse forwarding을 지원하므로, 아웃바운드 SSH의 포트 22가 차단된 네트워크에서도 사용할 수 있습니다. 무료 플랜은 60분 후 연결이 종료되고 재연결 시 새 URL이 사용되며, Pro 플랜에서는 영구 터널과 사용자 지정 도메인을 사용할 수 있습니다.<sup>[[21]](#references)[[22]](#references)</sup>

```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```

Pro에서는 custom domain과 persistent tunnel을 요청할 수 있습니다.<sup>[[22]](#references)</sup> 명령어를 loop로 감싸 임시 tunnel을 자동으로 재사용할 수 있습니다.

## Threat intel & OPSEC notes

공격자들은 Cloudflare의 인증이 필요 없는 `trycloudflare.com` endpoint를 포함해 ephemeral tunneling을 악용하여 임시 인프라를 통해 Remote Access Trojan을 유포해 왔습니다. Proofpoint는 2024년 2월 처음 관찰된 활동을 보고했으며, Xworm, AsyncRAT, VenomRAT, GuLoader, Remcos가 관련되어 있다고 밝혔습니다. 또한 임시 tunnel은 정적 blocklist에 의존하는 방어를 어렵게 만든다고 지적했습니다.<sup>[[23]](#references)</sup> tunnel과 domain을 선제적으로 교체하고, 사용 중인 tunneler로 향하는 외부 DNS 조회의 징후를 모니터링하여 blue-team의 탐지나 인프라 차단 시도를 조기에 포착할 수 있도록 하세요.

## References

- [1] [Serveo 문서](https://serveo.net/docs/)
- [2] [SocketXP 문서 - 시작하기](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [ngrok Agent 명령줄 인터페이스](https://ngrok.com/docs/agent/cli)
- [4] [ngrok FAQ](https://ngrok.com/docs/faq)
- [5] [Telebit.js 레거시 CLI 도움말](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [LocalXpose 문서](https://localxpose.gitbook.io/docs)
- [8] [Expose - 사이트 공유](https://expose.dev/docs/client/sharing)
- [9] [Expose - TCP 포트 공유](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [localtunnel/localtunnel 저장소](https://github.com/localtunnel/localtunnel)
- [11] [Cloudflare 문서 - Cloudflare Tunnel 설정](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Cloudflare Tunnel 개요](https://developers.cloudflare.com/tunnel/)
- [13] [Cloudflare 문서 - 유용한 tunnel 명령어](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Cloudflare 문서 - 라우팅](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Cloudflare 문서 - 구성 파일](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Cloudflare Access 정책](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Cloudflare 문서 - 실행 매개변수](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Tailscale Serve 명령어](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Tailscale Funnel 명령어](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [fatedier/frp - Fast Reverse Proxy 저장소](https://github.com/fatedier/frp)
- [21] [Pinggy 문서 - 사용법](https://pinggy.io/docs/usages/)
- [22] [Pinggy - 간편한 Localhost Tunnel](https://pinggy.io/)
- [23] [Proofpoint - 위협 행위자가 Cloudflare Tunnel을 악용해 RAT 유포](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
- [24] [Cloudflare 문서 - Tunnel 라우팅 및 지원 프로토콜](https://developers.cloudflare.com/tunnel/concepts/routing/)
{{#include ../banners/hacktricks-training.md}}
