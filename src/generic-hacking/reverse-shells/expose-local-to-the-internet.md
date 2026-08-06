# ローカルをインターネットに公開する

{{#include ../../banners/hacktricks-training.md}}

**このページの目的は、他のサーバーに何もインストールせず（必要な場合はローカルにのみインストールして）、少なくともローカルの raw TCP ポートとローカルの Web（HTTP）をインターネットに公開できる代替手段を提案することです。**

## **Serveo**

[https://serveo.net/](https://serveo.net/) では、複数の HTTP およびポートフォワーディング機能を**無料で**利用できます。
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

[https://www.socketxp.com/download](https://www.socketxp.com/download) から、tcp と http を公開できます：
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

[https://ngrok.com/](https://ngrok.com/) では、http および tcp ポートを公開できます:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

[https://telebit.cloud/](https://telebit.cloud/) では、http および tcp ポートを公開できます:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

[https://localxpose.io/](https://localxpose.io/) では、複数の http およびポートフォワーディング機能を**無料で**利用できます。
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

[https://expose.dev/](https://expose.dev/) から、http および tcp ポートを公開できます:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

[https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) を使用すると、http を無料で公開できます:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Cloudflare の `cloudflared` CLI は、高速なデモ向けに認証不要の「Quick」tunnel を作成したり、自分の domain/hostname に紐付けた named tunnel を作成したりできます。HTTP(S) reverse proxy に加えて、Cloudflare の edge 経由で routing される raw TCP mapping もサポートしています。<sup>[[1]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
Named tunnels では、`tunnel.yml` 内に複数の ingress ルール（HTTP、SSH、RDP など）を定義でき、Cloudflare Access によるサービスごとのアクセスポリシーに対応し、永続化のために systemd containers として実行できます。Quick Tunnels は匿名かつ一時的です。phishing payload staging や webhook テストには最適ですが、Cloudflare は uptime を保証していません。<sup>[[1]](#references)</sup>

## Tailscale Funnel / Serve

Tailscale v1.52+ には、統合された `tailscale serve`（tailnet 内で共有）と `tailscale funnel`（より広範なインターネットに公開）のワークフローが搭載されています。どちらのコマンドも、automatic TLS と短い `*.ts.net` hostname を使用して、HTTP(S) の reverse proxy または raw TCP の forwarding を実行できます。<sup>[[3]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
`--bg`を使用すると、フォアグラウンドプロセスを維持せずに設定を永続化できます。また、`tailscale funnel status`を使用すると、public internetから到達可能なサービスを監査できます。Funnelはlocal node上でTLSを終端するため、credential prompts、headers、mTLS enforcementはすべて自分の管理下に置けます。

## Fast Reverse Proxy (frp)

`frp`は、rendezvous server（`frps`）とclient（`frpc`）を自分で管理できるself-hostedの選択肢です。すでにVPSを所有しており、決定論的なdomains/portsを使用したいred teamsに適しています。

<details>
<summary>frps/frpc設定の例</summary>
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

最近のリリースでは、QUIC transport、token/OIDC auth、bandwidth caps、health checks、Go-template-based range mappingsが追加されています。これにより、異なるホスト上のimplantに対応付けた複数のlistenerをすばやく立ち上げるのに役立ちます。<sup>[[4]](#references)</sup>

## Pinggy（SSH-based）

PinggyはTCP/443経由でSSH-accessible tunnelを提供するため、HTTPSのみを許可するcaptive proxyの背後でも動作します。無料tierではsessionが60分間持続し、quick demoやwebhook relay用にscript化できます。<sup>[[5]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
有料 tier では custom domains と、より長期間有効な tunnels をリクエストできます。また、コマンドを loop でラップすることで、tunnels を自動的に再利用できます。

## Threat intel と OPSEC に関する注意事項

Adversaries は ephemeral tunneling、特に認証不要の Cloudflare の `trycloudflare.com` endpoints を悪用し、Remote Access Trojan payloads を stage したり、C2 infrastructure を隠したりするケースをますます増やしています。Proofpoint は 2024 年 2 月以降の campaigns を追跡し、download stages の参照先を短期間だけ有効な TryCloudflare URLs にすることで、AsyncRAT、Xworm、VenomRAT、GuLoader、Remcos を拡散していたことを確認しました。これにより、従来の static blocklists は大幅に効果が低下します。tunnels と domains は事前にローテーションすることを検討してください。また、使用中の tunneler への外部 DNS lookups を監視し、blue-team による detection や infrastructure blocking attempts を早期に発見できるようにしてください。<sup>[[2]](#references)</sup>

## References

- [1] [Cloudflare Docs - Create a locally-managed tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [2] [Proofpoint - Threat Actor Abuses Cloudflare Tunnels to Deliver RATs](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
- [3] [Tailscale - Reintroducing Serve and Funnel](https://tailscale.com/blog/reintroducing-serve-funnel)
- [4] [fatedier/frp - Fast Reverse Proxy repository](https://github.com/fatedier/frp)
- [5] [Pinggy Documentation - Usage](https://pinggy.io/docs/usages/)

{{#include ../../banners/hacktricks-training.md}}
