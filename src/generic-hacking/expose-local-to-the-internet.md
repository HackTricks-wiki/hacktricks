# ローカルをインターネットに公開する

{{#include ../banners/hacktricks-training.md}}

**このページの目的は、他のサーバーに何もインストールせずに（必要な場合はローカルにのみインストールして）、ローカルのraw TCPポートとローカルのWeb（HTTP）をインターネットに公開するための代替手段を提案することです。**

公開リレーを介してサービスを公開するのではなく、ホスト間で転送する方法については、[Tunneling and Port Forwarding](tunneling-and-port-forwarding.md)を参照してください。

## **Serveo**

Serveoのドキュメントでは、HTTPエンドポイント向けのSSH forwardingと、private/public TCP forwardingについて説明されています。ポート`0`を指定すると、anonymous sessionでもランダムなpublic TCP portが割り当てられますが、これらのsessionには時間と接続数の制限があります。任意のpublic TCP portを指定するには、有料アカウントが必要です。<sup>[[1]](#references)</sup>

```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```

## SocketXP

SocketXPのgetting-started guideには、TCPおよびHTTPトンネル用の`socketxp connect tcp://localhost:22`と`socketxp connect http://localhost:8080`が記載されています。まず、agentをportal tokenで認証します。<sup>[[2]](#references)</sup>

```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```

## Ngrok

ngrokのCLIではHTTPトンネルとTCPトンネルがドキュメント化されています。TCPエンドポイントにはアカウントで予約済みのTCPアドレスが必要です。無料プランでも有効な支払い方法の登録が必要ですが、FAQによると課金はされません。<sup>[[3]](#references)[[4]](#references)</sup>

```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```

## Telebit

従来の Telebit.js CLI のヘルプには、HTTPS 転送用の `telebit http <port>` と、raw TCP 用の `telebit tcp <local> [remote]` が記載されています。利用可能かどうかは、デプロイ環境と relay によって異なります。<sup>[[5]](#references)</sup>

```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```

## LocalXpose

LocalXposeの現行サイトでは、`loclx tunnel http --to 3000`の使い方を説明し、HTTP/TLS/TCP/UDPに対応していると記載しています。また、無料プランは個人利用や軽度の商用利用を対象としており、TCP tunnelingは有料プランの機能であるとしています。<sup>[[6]](#references)[[7]](#references)</sup>

```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```

## Expose

Exposeでは、HTTP/HTTPSのローカルURL向けの`expose share`と、PRO専用のTCPポート向けコマンド`expose share-port`が紹介されています。<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```

## Localtunnel

公式の localtunnel リポジトリでは、テスト用に localhost を公開する方法が説明されており、以下の NPX コマンドが記載されています。<sup>[[10]](#references)</sup>

```bash
# Expose web in port 8000
npx localtunnel --port 8000
```

## Cloudflare Tunnel (cloudflared)

Cloudflareの現在のドキュメントでは、ローカル開発向けに認証不要の「Quick」トンネルが紹介されており、製品概要には、公開に対応するプロトコルとしてHTTP、HTTPS、TCP、SSH、RDPが記載されています。<sup>[[11]](#references)[[12]](#references)</sup> HTTP(S)とは異なり、公開されたTCP、SSH、RDPのルートには標準クライアントから直接接続できません。Cloudflareでは接続側のクライアントにも`cloudflared`が必要なため、これらのルートは、このページで求める「raw TCP向けにクライアントのインストールが不要」という要件を満たしません。<sup>[[24]](#references)</sup>

ローカルで管理する名前付きトンネルについて、Cloudflareは` tunnel login`、`create`、`route dns`、および`--config ... run ...`のワークフローをドキュメントで説明しています。<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```

Named tunnels では YAML で複数の ingress rules を定義できます。Cloudflare Access policies で公開アプリケーションへのアクセスを制御でき、Cloudflare は connector を実行するための service と Docker のデプロイ方法をドキュメント化しています。Quick Tunnels は匿名で一時的なテスト用トンネルで、同時リクエスト数は 200 件まで、Server-Sent Events (SSE) はサポートされません。<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

Tailscale の現在の CLI では、tailnet 内のみの共有に Serve、一般公開の共有に Funnel を使用します。コマンドは HTTP/HTTPS の reverse-proxy ターゲットと TCP forwarding に対応しています。Funnel の raw TCP mode で使用できるポートは 443、8443、10000 に限られます。<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```

`--bg`を使用すると、フォアグラウンドのプロセスを維持せずに設定を永続化できます。また、`tailscale funnel status`を使用すると、パブリックインターネットから到達可能なサービスを監査できます。HTTPS Funnelのターゲットについて、Tailscaleのドキュメントでは、リクエストをローカルサービスに転送する前に、ローカルノードでTLSを終端すると説明されています。<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp`は、ランデブーサーバー（`frps`）とクライアント（`frpc`）を自分で管理するセルフホスト型の選択肢です。ドキュメントでは、NATやファイアウォールの背後にあるローカルサービスを、固定のリモートポートやドメインに転送する方法が説明されています。<sup>[[20]](#references)</sup>

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

現在のプロジェクトドキュメントには、QUIC transport、token/OIDC authentication、bandwidth limits、health checks、Go-template range mappings が含まれています。これらのオプションを使用する前に、デプロイに対応するリリースのドキュメントを確認してください。<sup>[[20]](#references)</sup>

## Pinggy（SSHベース）

Pinggyはポート443経由のSSH reverse forwardingをドキュメント化しているため、送信SSHのポート22がブロックされているネットワークでも利用できる場合があります。無料プランは60分後にタイムアウトし、再接続すると新しいURLが割り当てられます。一方、Proでは永続的なトンネルとカスタムドメインが利用できます。<sup>[[21]](#references)[[22]](#references)</sup>

```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```

Proでは、カスタムドメインと永続的なトンネルをリクエストできます。<sup>[[22]](#references)</sup> コマンドをループで囲めば、一時的なトンネルを自動的に再利用できます。

## 脅威インテリジェンスとOPSECに関する注意事項

攻撃者は一時的なトンネルを悪用しており、Cloudflareの認証不要な `trycloudflare.com` エンドポイントを通じて、仮設インフラからRemote Access Trojanを配信した事例もあります。Proofpointは、2024年2月に初めて確認された活動として、Xworm、AsyncRAT、VenomRAT、GuLoader、Remcosが関与していたと報告し、一時的なトンネルは静的なブロックリストに依存する防御を困難にすると指摘しました。<sup>[[23]](#references)</sup> トンネルやドメインを先回りしてローテーションすることを検討し、使用中のトンネラーへの外部DNS問い合わせなど、特徴的な兆候を監視して、blue teamによる検知やインフラのブロックを試みる動きを早期に把握しましょう。

## References

- [1] [Serveoのドキュメント](https://serveo.net/docs/)
- [2] [SocketXPのドキュメント - はじめに](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [ngrok Agentのコマンドラインインターフェース](https://ngrok.com/docs/agent/cli)
- [4] [ngrokのよくある質問](https://ngrok.com/docs/faq)
- [5] [Telebit.jsの旧CLIヘルプ](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [LocalXposeのドキュメント](https://localxpose.gitbook.io/docs)
- [8] [Expose - サイトの共有](https://expose.dev/docs/client/sharing)
- [9] [Expose - TCPポートの共有](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [localtunnel/localtunnelリポジトリ](https://github.com/localtunnel/localtunnel)
- [11] [Cloudflareのドキュメント - Cloudflare Tunnelのセットアップ](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Cloudflare Tunnelの概要](https://developers.cloudflare.com/tunnel/)
- [13] [Cloudflareのドキュメント - 便利なトンネルコマンド](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Cloudflareのドキュメント - ルーティング](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Cloudflareのドキュメント - 設定ファイル](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Cloudflare Accessポリシー](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Cloudflareのドキュメント - 実行パラメーター](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Tailscale Serveコマンド](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Tailscale Funnelコマンド](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [fatedier/frp - Fast Reverse Proxyリポジトリ](https://github.com/fatedier/frp)
- [21] [Pinggyのドキュメント - 使用方法](https://pinggy.io/docs/usages/)
- [22] [Pinggy - シンプルなlocalhostトンネル](https://pinggy.io/)
- [23] [Proofpoint - 脅威アクターがCloudflare Tunnelsを悪用してRATを配信](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
- [24] [Cloudflareのドキュメント - トンネルのルーティングとサポート対象プロトコル](https://developers.cloudflare.com/tunnel/concepts/routing/)
{{#include ../banners/hacktricks-training.md}}
