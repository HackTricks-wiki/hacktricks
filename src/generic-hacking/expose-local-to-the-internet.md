# ローカルをインターネットに公開する

{{#include ../banners/hacktricks-training.md}}

**このページの目的は、別のサーバーに何もインストールせず（必要な場合はローカルにのみインストールして）、ローカルの raw TCP ポートとローカルの Web サービス（HTTP）を少なくともインターネットに公開できる代替手段を提案することです。**

## **Serveo**

Serveo のドキュメントでは、HTTP エンドポイント向けの SSH forwarding と、プライベート／パブリックな TCP forwarding について説明されています。80/443 以外のパブリック TCP ポート（ランダムなポートを割り当てるポート 0 を含む）をリクエストするには、登録ユーザーである必要があります。<sup>[[1]](#references)</sup>

```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```

## SocketXP

SocketXP の getting-started guide では、TCP および HTTP トンネル用に `socketxp connect tcp://localhost:22` と `socketxp connect http://localhost:8080` が記載されています。agent は事前に portal token で認証されます。<sup>[[2]](#references)</sup>

```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```

## Ngrok

ngrok の CLI では HTTP および TCP トンネルが説明されています。FAQ によると、無料プランの TCP エンドポイントを利用するには有効な支払い方法の登録が必要ですが、カードに請求されることはありません。<sup>[[3]](#references)[[4]](#references)</sup>

```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```

## Telebit

旧版の Telebit.js CLI ヘルプには、HTTPS 転送用の `telebit http <port>` と、raw TCP 用の `telebit tcp <local> [remote]` が記載されています。利用可能かどうかは、デプロイ環境とリレーによって異なります。<sup>[[5]](#references)</sup>

```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```

## LocalXpose

LocalXposeの現在のサイトでは、`loclx tunnel http --to 3000`の使い方が説明され、HTTP/TLS/TCP/UDPに対応していると記載されています。また、無料プランは個人利用や小規模な商用利用を対象としており、TCPトンネリングは有料プランの機能とされています。<sup>[[6]](#references)[[7]](#references)</sup>

```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```

## 公開

Expose では、HTTP/HTTPS のローカル URL 用に `expose share`、TCP ポート用に PRO 限定の `expose share-port` コマンドが提供されています。<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```

## Localtunnel

公式の localtunnel リポジトリでは、テスト用に localhost を公開する方法を説明しており、以下の NPX コマンドを記載しています。<sup>[[10]](#references)</sup>

```bash
# Expose web in port 8000
npx localtunnel --port 8000
```

## Cloudflare Tunnel (cloudflared)

Cloudflareの現在のドキュメントでは、ローカル開発向けに認証不要の「Quick」トンネルが紹介されており、製品概要では公開プロトコルとしてHTTP、HTTPS、TCP、SSH、RDPが挙げられています。<sup>[[11]](#references)[[12]](#references)</sup>

ローカルで管理する名前付きトンネルについて、Cloudflareは `tunnel login`、`create`、`route dns`、および `--config ... run ...` を使用するワークフローを説明しています。<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```

Named tunnels では YAML で複数の ingress ルールを定義できます。Cloudflare Access policies で公開アプリケーションへのアクセスを制御でき、Cloudflare は connector の実行方法として service および Docker でのデプロイ手順を公開しています。Quick Tunnels は匿名で一時的なテスト用トンネルで、同時リクエスト数は 200 件まで、Server-Sent Events (SSE) はサポートされません。<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

Tailscale の現行 CLI では、tailnet 内のみの共有には Serve、公開共有には Funnel を使います。コマンドは HTTP/HTTPS の reverse-proxy 接続先と TCP forwarding に対応しています。Funnel の raw TCP モードで使用できるポートは 443、8443、10000 に限られます。<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```

`--bg`を使用すると、フォアグラウンドプロセスを維持せずに設定を永続化できます。また、`tailscale funnel status`を使用すると、パブリックインターネットから到達可能なサービスを監査できます。HTTPS Funnelのターゲットについて、Tailscaleのドキュメントでは、ローカルサービスにリクエストを転送する前に、ローカルノードでTLSを終端すると説明されています。<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp`は、ランデブーサーバー（`frps`）とクライアント（`frpc`）を自分で管理するセルフホスト型の選択肢です。そのドキュメントでは、NATまたはファイアウォールの背後にあるローカルサービスを、固定のリモートポートやドメインを使って転送する方法が説明されています。<sup>[[20]](#references)</sup>

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

現在のプロジェクトドキュメントには、QUIC transport、token/OIDC認証、帯域幅制限、health check、Go-templateのrange mappingが含まれています。これらのオプションを使用する前に、デプロイ環境に対応するリリースのドキュメントを確認してください。<sup>[[20]](#references)</sup>

## Pinggy（SSHベース）

Pinggyのドキュメントには、port 443経由のSSH reverse forwardingが記載されているため、outboundのport 22でのSSH通信がブロックされているネットワークでも動作する可能性があります。無料プランは60分後にタイムアウトし、再接続すると新しいURLが割り当てられます。一方、Proではpersistent tunnelとcustom domainが利用できます。<sup>[[21]](#references)[[22]](#references)</sup>

```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```

Proではカスタムドメインと永続的なトンネルをリクエストできます。<sup>[[22]](#references)</sup> コマンドをループで囲めば、一時的なトンネルを自動的に再利用できます。

## Threat intel & OPSECに関するメモ

攻撃者は、一時的なインフラを通じてRemote Access Trojansを配信するために、Cloudflareの認証不要な`trycloudflare.com`エンドポイントを含む、一時的なトンネリングを悪用しています。Proofpointは、2024年2月に初めて確認された活動として、Xworm、AsyncRAT、VenomRAT、GuLoader、Remcosを挙げ、一時的なトンネルによって、静的なブロックリストに依存する防御が困難になると報告しました。<sup>[[23]](#references)</sup> トンネルやドメインを事前にローテーションすることを検討し、使用しているトンネラーへの外部DNSルックアップという明確な兆候を監視して、blue-teamによる検知やインフラのブロックを試みる動きを早期に把握できるようにしましょう。

## References

- [1] [Serveoドキュメント](https://serveo.net/docs/)
- [2] [SocketXPドキュメント - はじめに](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [ngrok Agentコマンドラインインターフェース](https://ngrok.com/docs/agent/cli)
- [4] [ngrok FAQ](https://ngrok.com/docs/faq)
- [5] [Telebit.js旧版CLIヘルプ](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [LocalXposeドキュメント](https://localxpose.gitbook.io/docs)
- [8] [Expose - サイトの共有](https://expose.dev/docs/client/sharing)
- [9] [Expose - TCPポートの共有](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [localtunnel/localtunnelリポジトリ](https://github.com/localtunnel/localtunnel)
- [11] [Cloudflareドキュメント - Cloudflare Tunnelのセットアップ](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Cloudflare Tunnelの概要](https://developers.cloudflare.com/tunnel/)
- [13] [Cloudflareドキュメント - 便利なトンネルコマンド](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Cloudflareドキュメント - ルーティング](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Cloudflareドキュメント - 設定ファイル](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Cloudflare Accessポリシー](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Cloudflareドキュメント - 実行パラメーター](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Tailscale Serveコマンド](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Tailscale Funnelコマンド](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [fatedier/frp - Fast Reverse Proxyリポジトリ](https://github.com/fatedier/frp)
- [21] [Pinggyドキュメント - 使用方法](https://pinggy.io/docs/usages/)
- [22] [Pinggy - シンプルなローカルホストトンネル](https://pinggy.io/)
- [23] [Proofpoint - 脅威アクターがCloudflare Tunnelsを悪用してRATを配信](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
{{#include ../banners/hacktricks-training.md}}
