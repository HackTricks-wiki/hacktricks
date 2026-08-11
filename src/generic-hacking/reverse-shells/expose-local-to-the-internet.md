# 将本地服务暴露到互联网

{{#include ../../banners/hacktricks-training.md}}

**本页面的目标是提出一些替代方案，使本地 raw TCP 端口和本地 Web 服务（HTTP）至少能够暴露到互联网，而无需在另一台服务器上安装任何东西（如有需要，仅在本地安装）。**

## **Serveo**

Serveo 的文档介绍了用于 HTTP 端点的 SSH 转发，以及私有/公共 TCP 转发；请求非 80/443 的公共 TCP 端口（包括用于随机端口的端口 0）需要注册用户。<sup>[[1]](#references)</sup>
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

SocketXP 的 getting-started guide 记录了用于 TCP 和 HTTP tunnels 的 `socketxp connect tcp://localhost:22` 与 `socketxp connect http://localhost:8080`；首先需要使用 portal token 对 agent 进行身份验证。<sup>[[2]](#references)</sup>
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

ngrok 的 CLI 文档介绍了 HTTP 和 TCP 隧道；其 FAQ 说明，免费层 TCP endpoints 需要有效的付款方式，但不会从卡中扣款。<sup>[[3]](#references)[[4]](#references)</sup>
```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```
## Telebit

旧版 Telebit.js CLI 帮助文档说明，`telebit http <port>` 用于 HTTPS forwarding，`telebit tcp <local> [remote]` 用于 raw TCP；具体可用性取决于部署方式和 relay。<sup>[[5]](#references)</sup>
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

LocalXpose 的当前网站记录了 `loclx tunnel http --to 3000`，列出了对 HTTP/TLS/TCP/UDP 的支持，并说明免费计划涵盖个人用途和轻量商业用途，而 TCP tunneling 是付费计划的功能。<sup>[[6]](#references)[[7]](#references)</sup>
```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```
## Expose

Expose 文档提供了用于 HTTP/HTTPS 本地 URL 的 `expose share`，以及仅限 PRO 的用于 TCP 端口的 `expose share-port` 命令。<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```
## Localtunnel

官方 localtunnel repository 描述了如何暴露 localhost 进行测试，并记录了下面的 NPX command。<sup>[[10]](#references)</sup>
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Cloudflare 当前文档展示了用于本地开发的无需身份验证的“Quick” tunnels，产品概览则将 HTTP、HTTPS、TCP、SSH 和 RDP 列为支持的发布协议。<sup>[[11]](#references)[[12]](#references)</sup>

对于本地管理的命名 tunnel，Cloudflare 记录了 `tunnel login`、`create`、`route dns` 以及 `--config ... run ...` 工作流程。<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```
Named tunnels 可以在 YAML 中定义多个 ingress 规则；Cloudflare Access policies 可以控制对已发布应用的访问，Cloudflare 也记录了用于运行 connectors 的 service 和 Docker 部署路径。Quick Tunnels 是匿名的临时测试 tunnels，并发请求数上限为 200，且不支持 Server-Sent Events (SSE)。<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

Tailscale 的当前 CLI 使用 Serve 在 tailnet 内部共享，使用 Funnel 进行公开共享。这些命令支持 HTTP/HTTPS reverse-proxy targets 和 TCP forwarding；Funnel 的 raw TCP mode 仅限于端口 443、8443 和 10000。<sup>[[18]](#references)[[19]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
使用 `--bg` 可在不保留前台进程的情况下持久化配置，并使用 `tailscale funnel status` 审计哪些服务可从公共互联网访问。对于 HTTPS Funnel 目标，Tailscale 文档说明，Tailscale 会先在本地节点终止 TLS，然后将请求转发到本地服务。<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp` 是一种 self-hosted 选项，你可以控制 rendezvous server（`frps`）和 client（`frpc`）；其文档介绍了如何将 NAT 或 firewall 后面的本地服务转发到具有确定性远程端口或域名的位置。<sup>[[20]](#references)</sup>

<details>
<summary>frps/frpc 配置示例</summary>
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

当前项目文档包含 QUIC transport、token/OIDC authentication、bandwidth limits、health checks 以及 Go-template range mappings；使用其中任何选项前，请先查阅与部署版本匹配的文档。<sup>[[20]](#references)</sup>

## Pinggy（基于 SSH）

Pinggy 说明了通过端口 443 进行 SSH reverse forwarding 的方法，因此它可以在出站 SSH 的 22 端口被阻止的网络中工作。其 free plan 在 60 分钟后超时，重新连接后会使用新的 URL，而 Pro 则增加了 persistent tunnels 和 custom domains。<sup>[[21]](#references)[[22]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```
你可以在 Pro 上请求 custom domains 和 persistent tunnels。<sup>[[22]](#references)</sup> 你可以通过将命令封装在循环中，自动回收临时 tunnels。

## Threat intel & OPSEC notes

Adversaries 曾滥用 ephemeral tunneling，包括 Cloudflare 未经身份验证的 `trycloudflare.com` endpoints，通过临时基础设施投递 Remote Access Trojans。Proofpoint 报告称，首次于 2024 年 2 月观察到相关活动，涉及 Xworm、AsyncRAT、VenomRAT、GuLoader 和 Remcos，并指出临时 tunnels 会使依赖静态 blocklists 的防御措施更加复杂。<sup>[[23]](#references)</sup> 建议主动轮换 tunnels 和 domains，并监控指向所用 tunneler 的明显外部 DNS 查询，以便及早发现 blue-team 的检测或基础设施阻断尝试。

## References

- [1] [Serveo Documentation](https://serveo.net/docs/)
- [2] [SocketXP Documentation - 入门](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [ngrok Agent 命令行界面](https://ngrok.com/docs/agent/cli)
- [4] [ngrok 常见问题](https://ngrok.com/docs/faq)
- [5] [Telebit.js legacy CLI 帮助](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [LocalXpose Documentation](https://localxpose.gitbook.io/docs)
- [8] [Expose - Sharing sites](https://expose.dev/docs/client/sharing)
- [9] [Expose - Sharing TCP ports](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [localtunnel/localtunnel repository](https://github.com/localtunnel/localtunnel)
- [11] [Cloudflare Docs - 设置 Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Cloudflare Tunnel 概览](https://developers.cloudflare.com/tunnel/)
- [13] [Cloudflare Docs - 实用 tunnel 命令](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Cloudflare Docs - Routing](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Cloudflare Docs - 配置文件](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Cloudflare Access policies](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Cloudflare Docs - Run parameters](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Tailscale Serve 命令](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Tailscale Funnel 命令](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [fatedier/frp - Fast Reverse Proxy repository](https://github.com/fatedier/frp)
- [21] [Pinggy Documentation - 用法](https://pinggy.io/docs/usages/)
- [22] [Pinggy - Simple Localhost Tunnels](https://pinggy.io/)
- [23] [Proofpoint - Threat Actor Abuses Cloudflare Tunnels to Deliver RATs](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
{{#include ../../banners/hacktricks-training.md}}
