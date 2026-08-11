# ローカルをインターネットに公開する

**このページの目的は、他のサーバーに何もインストールせずに（必要な場合はローカル側のみにインストールして）、少なくともローカルの raw TCP ポートとローカルの web（HTTP）をインターネットに公開できる代替手段を提案することです。**

## **Serveo**

Serveo のドキュメントでは、HTTP エンドポイント向けの SSH forwarding と、private/public TCP forwarding について説明されています。80/443 以外の public TCP ポート（ランダムなポートを指定するポート 0 を含む）を要求するには、登録済みユーザーが必要です。<sup>[[1]](#references)</sup>
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

SocketXPのgetting-started guideでは、TCPおよびHTTPトンネル用に`socketxp connect tcp://localhost:22`と`socketxp connect http://localhost:8080`が説明されています。agentはまずportal tokenで認証されます。<sup>[[2]](#references)</sup>
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

ngrokのCLIではHTTPおよびTCPトンネルについて説明されています。FAQによると、無料プランのTCPエンドポイントには有効な支払い方法が必要ですが、カードへの請求は発生しません。<sup>[[3]](#references)[[4]](#references)</sup>
```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```
## Telebit

レガシーな Telebit.js CLI のヘルプでは、HTTPS forwarding に `telebit http <port>`、raw TCP に `telebit tcp <local> [remote]` が記載されています。利用可能かどうかは deployment と relay に依存します。<sup>[[5]](#references)</sup>
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

LocalXposeの現在のサイトでは、`loclx tunnel http --to 3000`について説明されており、HTTP/TLS/TCP/UDPをサポートしていること、また無料プランは個人利用および小規模な商用利用を対象としており、TCP tunnelingは有料プランの機能であることが記載されています。<sup>[[6]](#references)[[7]](#references)</sup>
```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```
## Expose

Expose は HTTP/HTTPS のローカル URL 用に `expose share` を提供し、TCP ポート用には PRO 限定の `expose share-port` コマンドを提供します。<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```
## Localtunnel

公式の localtunnel repository では、testing のために localhost を公開する方法を説明しており、以下の NPX command を記載しています。<sup>[[10]](#references)</sup>
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Cloudflareの現在のドキュメントでは、local development向けに認証不要の「Quick」tunnelが示されており、製品概要には、サポートされる公開プロトコルとしてHTTP、HTTPS、TCP、SSH、RDPが挙げられています。<sup>[[11]](#references)[[12]](#references)</sup>

localで管理する名前付きtunnelについて、Cloudflareは` tunnel login`、`create`、`route dns`、および`--config ... run ...`のworkflowをドキュメント化しています。<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```
Named tunnels は YAML で複数の ingress rules を定義できます。Cloudflare Access policies は公開された applications への access を制御でき、Cloudflare は connectors を実行するための service および Docker deployment paths を文書化しています。Quick Tunnels は匿名の一時的な testing tunnels で、同時 200 リクエストの制限があり、Server-Sent Events (SSE) はサポートしません。<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

現在の Tailscale CLI では、tailnet 専用の共有に Serve を、公開共有に Funnel を使用します。コマンドは HTTP/HTTPS reverse-proxy targets と TCP forwarding に対応しています。Funnel の raw TCP mode は、ポート 443、8443、10000 に制限されています。<sup>[[18]](#references)[[19]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
`--bg`を使用すると、フォアグラウンドプロセスを維持せずに設定を永続化できます。また、`tailscale funnel status`を使用すると、public internetから到達可能なサービスを監査できます。HTTPS Funnelターゲットの場合、Tailscaleのドキュメントでは、リクエストをlocal serviceに転送する前にlocal nodeでTLS terminationを行うと説明されています。<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp`は、rendezvous server（`frps`）とclient（`frpc`）を自分で管理するself-hosted optionです。そのドキュメントでは、NATまたはfirewallの背後にあるlocal serviceを、決定論的なremote port/domainを使用してforwardする方法が説明されています。<sup>[[20]](#references)</sup>

<details>
<summary>frps/frpcの設定例</summary>
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

現在のプロジェクトドキュメントには、QUIC transport、token/OIDC 認証、帯域幅制限、health checks、Go-template の range マッピングが含まれています。これらのオプションを使用する前に、デプロイ環境に対応する release を確認してください。<sup>[[20]](#references)</sup>

## Pinggy (SSH-based)

Pinggy は port 443 経由の SSH reverse forwarding をドキュメント化しているため、outbound SSH の port 22 がブロックされているネットワークでも動作します。無料プランは 60 分後に timeout し、再接続すると新しい URL が使用されます。一方、Pro では persistent tunnels と custom domains が追加されます。<sup>[[21]](#references)[[22]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```
Pro では、カスタムドメインと永続的なトンネルをリクエストできます。<sup>[[22]](#references)</sup> コマンドをループでラップすることで、一時的なトンネルを自動的に再利用できます。

## 脅威インテリジェンスとOPSECに関する注意事項

Adversaries は、一時的なインフラを通じて Remote Access Trojans を配信するために、Cloudflare の認証不要な `trycloudflare.com` エンドポイントなど、ephemeral tunneling を悪用しています。Proofpoint は、2024 年 2 月に初めて観測された活動として、Xworm、AsyncRAT、VenomRAT、GuLoader、Remcos が関与していたことを報告し、一時的なトンネルによって、静的な blocklist に依存する防御が複雑になると指摘しました。<sup>[[23]](#references)</sup> トンネルとドメインは事前にローテーションすることを検討し、使用中の tunneler への外部 DNS lookup という兆候を監視して、blue-team による検知やインフラのブロック試行を早期に発見できるようにしてください。

## References

- [1] [Serveo ドキュメント](https://serveo.net/docs/)
- [2] [SocketXP ドキュメント - はじめに](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [ngrok Agent コマンドラインインターフェース](https://ngrok.com/docs/agent/cli)
- [4] [ngrok FAQ](https://ngrok.com/docs/faq)
- [5] [Telebit.js legacy CLI ヘルプ](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [LocalXpose ドキュメント](https://localxpose.gitbook.io/docs)
- [8] [Expose - サイトの共有](https://expose.dev/docs/client/sharing)
- [9] [Expose - TCP ポートの共有](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [localtunnel/localtunnel リポジトリ](https://github.com/localtunnel/localtunnel)
- [11] [Cloudflare Docs - Cloudflare Tunnel のセットアップ](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Cloudflare Tunnel の概要](https://developers.cloudflare.com/tunnel/)
- [13] [Cloudflare Docs - 便利なトンネルコマンド](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Cloudflare Docs - ルーティング](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Cloudflare Docs - 設定ファイル](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Cloudflare Access ポリシー](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Cloudflare Docs - 実行パラメーター](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Tailscale Serve コマンド](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Tailscale Funnel コマンド](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [fatedier/frp - Fast Reverse Proxy リポジトリ](https://github.com/fatedier/frp)
- [21] [Pinggy ドキュメント - 使用方法](https://pinggy.io/docs/usages/)
- [22] [Pinggy - シンプルな Localhost トンネル](https://pinggy.io/)
- [23] [Proofpoint - Threat Actor による Cloudflare Tunnels の悪用と RAT の配信](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
{{#include ../../banners/hacktricks-training.md}}
