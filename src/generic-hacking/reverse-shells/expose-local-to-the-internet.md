# 将本地服务暴露到互联网

{{#include ../../banners/hacktricks-training.md}}

**本页面旨在提出一些替代方案，使本地 raw TCP 端口和本地 Web（HTTP）至少能够暴露到互联网，而无需在另一台服务器上安装任何东西（如有需要，仅需在本地安装）。**

## **Serveo**

通过 [https://serveo.net/](https://serveo.net/)，可以**免费**使用多种 HTTP 和 port forwarding 功能。
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

从 [https://www.socketxp.com/download](https://www.socketxp.com/download) 下载后，可以暴露 tcp 和 http：
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

通过 [https://ngrok.com/](https://ngrok.com/)，可以暴露 http 和 tcp 端口：
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

通过 [https://telebit.cloud/](https://telebit.cloud/)，可以暴露 http 和 tcp 端口：
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

通过 [https://localxpose.io/](https://localxpose.io/)，可以**免费**使用多种 HTTP 和端口转发功能。
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

通过 [https://expose.dev/](https://expose.dev/)，可以暴露 http 和 tcp 端口：
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

从 [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) 可免费 expose http：
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Cloudflare 的 `cloudflared` CLI 可以创建无需认证的“Quick” tunnels，用于快速演示，也可以创建绑定到你自己的 domain/hostnames 的命名 tunnels。它支持 HTTP(S) reverse proxies，以及通过 Cloudflare edge 路由的 raw TCP mappings。<sup>[[1]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
Named tunnels 允许你在 `tunnel.yml` 中定义多个 ingress 规则（HTTP、SSH、RDP 等），通过 Cloudflare Access 支持按服务配置访问策略，并且可以作为 systemd 容器运行以实现持久化。Quick Tunnels 是匿名且临时的——非常适合 phishing payload staging 或 webhook 测试，但 Cloudflare 不保证其 uptime。<sup>[[1]](#references)</sup>

## Tailscale Funnel / Serve

Tailscale v1.52+ 提供统一的 `tailscale serve`（在 tailnet 内共享）和 `tailscale funnel`（向更广泛的互联网发布）工作流。这两个命令都可以反向代理 HTTP(S) 或转发原始 TCP，并自动配置 TLS 和简短的 `*.ts.net` 主机名。<sup>[[3]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
使用 `--bg` 在不保留前台进程的情况下持久化配置，并使用 `tailscale funnel status` 审计哪些服务可从公共互联网访问。由于 Funnel 会在本地节点终止 TLS，因此任何凭据提示、headers 或 mTLS enforcement 都可以由你控制。

## Fast Reverse Proxy (frp)

`frp` 是一种 self-hosted 选项，你可以控制 rendezvous server（`frps`）和 client（`frpc`）。对于已经拥有 VPS 并希望使用确定性 domains/ports 的 red teams 来说，它非常实用。

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

近期版本新增了 QUIC transport、token/OIDC auth、bandwidth caps、health checks 以及基于 Go-template 的 range mappings，可用于快速搭建多个 listeners，并将其映射回不同主机上的 implants。<sup>[[4]](#references)</sup>

## Pinggy（基于 SSH）

Pinggy 提供可通过 SSH 访问的 TCP/443 tunnels，因此即使位于只允许 HTTPS 的 captive proxies 后方也能正常工作。免费 tier 中的 sessions 可持续 60 分钟，并且可以通过脚本实现快速 demos 或 webhook relays。<sup>[[5]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
付费 tier 支持申请 custom domains 和更长生命周期的 tunnels；或者将命令包装在循环中，以便自动回收 tunnels。

## Threat intel & OPSEC notes

攻击者越来越多地滥用 ephemeral tunneling（尤其是 Cloudflare 未经身份验证的 `trycloudflare.com` endpoints）来部署 Remote Access Trojan payloads 并隐藏 C2 infrastructure。Proofpoint 追踪到自 2024 年 2 月以来的多个 campaigns：攻击者将 download stages 指向短生命周期的 TryCloudflare URLs，以分发 AsyncRAT、Xworm、VenomRAT、GuLoader 和 Remcos，使传统的静态 blocklists 变得远不够有效。请考虑主动轮换 tunnels 和 domains，同时监控指向所使用 tunneler 的外部 DNS lookups，从而尽早发现 blue-team detection 或 infrastructure blocking attempts。<sup>[[2]](#references)</sup>

## References

- [1] [Cloudflare Docs - 创建由本地管理的 tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [2] [Proofpoint - Threat Actor Abuses Cloudflare Tunnels to Deliver RATs](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
- [3] [Tailscale - Reintroducing Serve and Funnel](https://tailscale.com/blog/reintroducing-serve-funnel)
- [4] [fatedier/frp - Fast Reverse Proxy repository](https://github.com/fatedier/frp)
- [5] [Pinggy Documentation - Usage](https://pinggy.io/docs/usages/)

{{#include ../../banners/hacktricks-training.md}}
