# ローカルをインターネットに公開する

{{#include ../../banners/hacktricks-training.md}}

**このページの目的は、他のサーバーに何もインストールせず（必要な場合はローカルにのみインストールして）、少なくともローカルの raw TCP ポートとローカルの web（HTTP）をインターネットに公開できる代替手段を提案することです。**

## **Serveo**

Serveo のドキュメントでは、HTTP endpoint 向けの SSH forwarding と、private/public TCP forwarding について説明されています。80/443 以外の public TCP port（ランダムな port 用の port 0 を含む）を要求するには、registered user が必要です。<sup>[[1]](#references)</sup>
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

SocketXPのgetting-started guideでは、TCPおよびHTTPトンネル用に`socketxp connect tcp://localhost:22`と`socketxp connect http://localhost:8080`が記載されています。agentは最初にportal tokenで認証されます。<sup>[[2]](#references)</sup>
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

ngrokのCLIではHTTPおよびTCPトンネルについて説明されています。FAQによると、free-tierのTCPエンドポイントには有効な支払い方法が必要ですが、カードに請求は発生しません。<sup>[[3]](#references)[[4]](#references)</sup>
```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```
## Telebit

legacy の Telebit.js CLI help では、HTTPS forwarding に `telebit http <port>`、raw TCP に `telebit tcp <local> [remote]` が記載されていますが、利用可能かどうかは deployment と relay に依存します。<sup>[[5]](#references)</sup>
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

LocalXposeの現在のサイトでは、`loclx tunnel http --to 3000`が案内され、HTTP/TLS/TCP/UDPのサポートが列挙されています。また、無料プランは個人利用および軽度の商用利用を対象としており、TCP tunnelingは有料プランの機能であると記載されています。<sup>[[6]](#references)[[7]](#references)</sup>
```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```
## Expose

Exposeは、HTTP/HTTPSのlocal URL向けの`expose share`と、TCPポート向けのPRO限定`expose share-port` commandを提供します。<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```
## Localtunnel

公式のlocaltunnel repositoryでは、testingのためにlocalhostを公開する方法が説明されており、以下のNPX commandが記載されています。<sup>[[10]](#references)</sup>
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Cloudflare の現在の docs では、local development 用の認証不要の「Quick」tunnel が案内されており、product overview にはサポートされる公開 protocol として HTTP、HTTPS、TCP、SSH、RDP が挙げられています。<sup>[[11]](#references)[[12]](#references)</sup>

locally managed named tunnel について、Cloudflare は `tunnel login`、`create`、`route dns`、および `--config ... run ...` の workflow をドキュメント化しています。<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```
Named tunnels は YAML で複数の ingress ルールを定義できます。Cloudflare Access policies は公開されたアプリケーションへのアクセスを制御でき、Cloudflare は connector を実行するための service および Docker の deployment パスをドキュメント化しています。Quick Tunnels は匿名で一時的な testing 用トンネルで、同時リクエスト数は 200 に制限され、Server-Sent Events (SSE) はサポートされません。<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

Tailscale の現在の CLI では、tailnet 内限定の共有には Serve、public な共有には Funnel を使用します。コマンドは HTTP/HTTPS reverse-proxy target と TCP forwarding をサポートします。Funnel の raw TCP mode はポート 443、8443、10000 に制限されています。<sup>[[18]](#references)[[19]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
`--bg` を使用すると、foreground process を維持せずに設定を永続化できます。また、`tailscale funnel status` を使用すると、public internet から到達可能なサービスを監査できます。HTTPS Funnel の target について、Tailscale は、リクエストを local service に転送する前に local node で TLS termination を行うことをドキュメントで説明しています。<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp` は、rendezvous server（`frps`）と client（`frpc`）を自分で管理する self-hosted option です。その documentation では、NAT または firewall の背後にある local services を、決定的な remote ports/domains で forwarding する方法を説明しています。<sup>[[20]](#references)</sup>

<details>
<summary>frps/frpc configuration の例</summary>
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

現在のプロジェクトドキュメントには、QUIC transport、token/OIDC authentication、bandwidth limits、health checks、Go-template range mappings が含まれています。これらのオプションを使用する前に、デプロイ環境に対応する release を確認してください。<sup>[[20]](#references)</sup>

## Pinggy (SSH-based)

Pinggy は port 443 経由の SSH reverse forwarding をドキュメント化しているため、outbound SSH の port 22 がブロックされている network でも利用できます。Free plan は 60 分後に timeout し、reconnect 後は新しい URL が使用されます。一方、Pro では persistent tunnels と custom domains が追加されます。<sup>[[21]](#references)[[22]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```
Pro では、custom domains と persistent tunnels をリクエストできます。<sup>[[22]](#references)</sup> コマンドを loop でラップすれば、一時的な tunnel を自動的に再利用できます。

## Threat intel & OPSEC notes

Adversaries は、Cloudflare の認証不要な `trycloudflare.com` endpoints を含む ephemeral tunneling を悪用し、一時的な infrastructure を通じて Remote Access Trojans を配信しています。Proofpoint は、2024 年 2 月に初めて観測された Xworm、AsyncRAT、VenomRAT、GuLoader、Remcos に関する活動を報告し、一時的な tunnel によって、静的な blocklist に依存する防御が複雑になると指摘しました。<sup>[[23]](#references)</sup> tunnel と domain は事前にローテーションすることを検討し、使用中の tunneler に対する外部 DNS lookup の特徴的な兆候を monitor して、blue-team による detection や infrastructure の blocking attempts を早期に発見できるようにしてください。

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
