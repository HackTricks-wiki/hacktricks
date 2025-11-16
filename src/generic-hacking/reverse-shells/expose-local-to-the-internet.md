# ローカルをインターネットに公開

{{#include ../../banners/hacktricks-training.md}}

**このページの目的は、少なくともローカルの生のTCPポートやローカルのWeb（HTTP）を、他のサーバーに何もインストールすることなく（必要ならローカル側のみでインストール）インターネットに公開するための代替手段を提案することです。**

## **Serveo**

From [https://serveo.net/](https://serveo.net/), いくつかのhttpおよびポートフォワーディング機能を**無料で**利用できます。
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

[https://www.socketxp.com/download](https://www.socketxp.com/download) からダウンロードでき、tcp と http を公開できます:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

[https://ngrok.com/](https://ngrok.com/) から、http と tcp ポートを公開できます:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

[https://telebit.cloud/](https://telebit.cloud/) から、http と tcp のポートを公開できます:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

公式サイト [https://localxpose.io/](https://localxpose.io/) によると、複数の http と port forwarding 機能を**無料で**利用できます。
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

[https://expose.dev/](https://expose.dev/) から、http と tcp ポートを公開できます:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

[https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) から、http を無料で公開できます:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Cloudflare の `cloudflared` CLI は、認証不要の "Quick" トンネルを作成して素早いデモを行ったり、独自のドメイン/ホスト名に紐付けられた名前付きトンネルを作成したりできます。HTTP(S) のリバースプロキシや、Cloudflare のエッジ経由でルーティングされる生の TCP マッピングにも対応しています。
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
Named tunnels は `tunnel.yml` 内に複数の ingress ルール（HTTP、SSH、RDP など）を定義でき、Cloudflare Access 経由でサービスごとのアクセスポリシーをサポートし、永続化のために systemd コンテナとして実行できます。Quick Tunnels は匿名かつ一時的で—phishing payload staging や webhook tests に最適ですが、Cloudflare は稼働時間を保証しません。

## Tailscale Funnel / Serve

Tailscale v1.52+ は統合された `tailscale serve`（share inside the tailnet）と `tailscale funnel`（publish to the wider internet）ワークフローを搭載しています。両コマンドとも自動 TLS と短い `*.ts.net` ホスト名で HTTP(S) のリバースプロキシまたは生の TCP フォワードが可能です。
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Use `--bg` を使うとフォアグラウンドプロセスを維持せずに設定を永続化でき、`tailscale funnel status` でパブリックインターネットから到達可能なサービスを監査できます。Funnel はローカルノードで TLS を終端するため、認証プロンプト、ヘッダ、あるいは mTLS の強制は引き続きあなたの管理下に置けます。

## Fast Reverse Proxy (frp)

`frp` は rendezvous サーバー（`frps`）とクライアント（`frpc`）を自分で管理するセルフホスト型のオプションです。既に VPS を所有していて、決まったドメイン／ポートを使いたい red teams に向いています。

<details>
<summary>frps/frpc のサンプル設定</summary>
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

最近のリリースでは、QUIC transport、token/OIDC auth、帯域幅の制限、ヘルスチェック、そしてGo-templateベースのrange mappingsが追加されました。これにより、異なるホスト上のimplantsにマップバックする複数のlistenersを素早く立ち上げるのに便利です。

## Pinggy (SSH-based)

PinggyはTCP/443経由でSSHアクセス可能なトンネルを提供するため、HTTPSのみを許可するcaptive proxiesの背後でも動作します。セッションは無料プランで60分継続し、クイックデモやwebhook relays用にスクリプト化できます。
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
有料プランではカスタムドメインやより長期間のトンネルをリクエストできます。また、コマンドをループで実行してトンネルを自動で再作成することもできます。

## 脅威インテリジェンスとOPSECの注意点

攻撃者は、エフェメラルトンネル（特にCloudflareの認証不要な `trycloudflare.com` エンドポイント）を悪用してRemote Access Trojanのペイロードをステージングしたり、C2インフラを隠蔽したりするケースが増えています。Proofpointは2024年2月以降、ダウンロード段階を短命のTryCloudflare URLに向けることでAsyncRAT、Xworm、VenomRAT、GuLoader、Remcosを配布するキャンペーンを追跡しており、従来の静的なブロックリストでは効果が薄くなっています。トンネルやドメインを積極的にローテーションすることを検討してください。また、使用しているトンネラーへの外部DNSルックアップ（特徴的な問い合わせ）を監視し、blue-teamによる検出やインフラ遮断の試みを早期に発見できるようにしてください。

## References

- [Cloudflare Docs - Create a locally-managed tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [Proofpoint - Threat Actor Abuses Cloudflare Tunnels to Deliver RATs](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)

{{#include ../../banners/hacktricks-training.md}}
