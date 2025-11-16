# 将本地服务暴露到互联网

{{#include ../../banners/hacktricks-training.md}}

**本页面的目标是提出一些替代方案，至少允许将本地原始 TCP 端口和本地网页 (HTTP) 暴露到互联网，而无需在另一台服务器上安装任何东西（如有需要，仅在本地安装）。**

## **Serveo**

From [https://serveo.net/](https://serveo.net/), 它提供若干 http 和端口转发功能，**免费**。
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

从 [https://www.socketxp.com/download](https://www.socketxp.com/download)，它允许公开 tcp 和 http：
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

来自 [https://ngrok.com/](https://ngrok.com/)，它允许暴露 http 和 tcp 端口：
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

来自 [https://telebit.cloud/](https://telebit.cloud/)，它允许暴露 http 和 tcp 端口：
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

来自 [https://localxpose.io/](https://localxpose.io/)，它允许多种 http 和 port forwarding 功能，**免费**。
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

来自 [https://expose.dev/](https://expose.dev/)，它允许暴露 http 和 tcp 端口：
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

来自 [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel)，它允许免费暴露 http:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Cloudflare's `cloudflared` CLI 可以创建未认证的 "Quick" 隧道用于快速演示，或创建绑定到你自己的 domain/hostnames 的命名隧道。它支持 HTTP(S) reverse proxies，以及通过 Cloudflare's edge 路由的原始 TCP 映射。
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
Named tunnels 允许你在 `tunnel.yml` 中定义多个 ingress 规则 (HTTP、SSH、RDP 等)，通过 Cloudflare Access 支持每个服务的访问策略，并可作为 systemd 容器运行以实现持久化。Quick Tunnels 是匿名且短暂的——非常适合 phishing payload staging 或 webhook tests，但 Cloudflare 不保证可用性。

## Tailscale Funnel / Serve

Tailscale v1.52+ 提供统一的 `tailscale serve`（在 tailnet 内共享）和 `tailscale funnel`（发布到更广泛的互联网）工作流。两个命令都可以反向代理 HTTP(S) 或转发原始 TCP，并提供自动 TLS 和短的 `*.ts.net` 主机名。
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
使用 `--bg` 在不保持前台进程的情况下持久化配置，使用 `tailscale funnel status` 审计哪些服务可从公网访问。由于 Funnel 在本地节点终止 TLS，任何凭证提示、头部或 mTLS 强制仍可由你控制。

## 快速反向代理 (frp)

`frp` 是一个自托管的选项，你可以控制 rendezvous server (`frps`) 和客户端 (`frpc`)。它非常适合已经拥有 VPS 并希望使用确定的域名/端口的 red teams。

<details>
<summary>frps/frpc 配置示例</summary>
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

最近的版本增加了 QUIC transport、token/OIDC auth、bandwidth caps、health checks 和 Go-template-based range mappings——便于快速启动多个 listeners 并将其映射回不同主机上的 implants。

## Pinggy (基于 SSH)

Pinggy 提供通过 SSH 可访问的隧道，走 TCP/443，因此即使位于只允许 HTTPS 的 captive proxies 后面也能工作。Sessions 在 free tier 上持续 60 分钟，且可以通过脚本自动化，用于快速演示或 webhook relays。
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
你可以在付费套餐中申请自定义域名和更长寿命的隧道，或者通过将命令包裹在循环中自动回收隧道。

## Threat intel & OPSEC notes

对手越来越频繁地滥用 ephemeral tunneling（尤其是 Cloudflare 未认证的 `trycloudflare.com` 端点）来部署 Remote Access Trojan payloads 并隐藏 C2 基础设施。Proofpoint 自 2024 年 2 月以来跟踪到的活动通过将下载阶段指向短期的 TryCloudflare URLs 推送了 AsyncRAT、Xworm、VenomRAT、GuLoader 和 Remcos，使得传统的静态 blocklists 效果大幅降低。建议主动 rotate tunnels 和 domains，同时监控对你正在使用的 tunneler 的外部 DNS 查询（external DNS lookups）等典型迹象，以便及早发现 blue-team 的检测或基础设施封锁尝试。

## References

- [Cloudflare Docs - Create a locally-managed tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [Proofpoint - Threat Actor Abuses Cloudflare Tunnels to Deliver RATs](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)

{{#include ../../banners/hacktricks-training.md}}
