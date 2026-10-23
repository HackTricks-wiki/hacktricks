# 将本地服务暴露到互联网

{{#include ../banners/hacktricks-training.md}}

**本页旨在介绍一些替代方案，让你至少能够将本地原始 TCP 端口和本地网站（HTTP）暴露到互联网上，而无需在另一台服务器上安装任何东西（如有需要，只需在本地安装）。**

如果要在主机之间转发，而不是通过公共中继发布服务，请参阅 [Tunneling and Port Forwarding](tunneling-and-port-forwarding.md)。

## **Serveo**

Serveo 的文档介绍了用于 HTTP 端点的 SSH 转发，以及私有/公共 TCP 转发。即使是匿名会话，端口 `0` 也会请求一个随机的公共 TCP 端口，但此类会话的时间和连接数限制较短；请求指定的公共 TCP 端口则需要付费账户。<sup>[[1]](#references)</sup>

```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```

## SocketXP

SocketXP 的入门指南记录了用于 TCP 和 HTTP 隧道的 `socketxp connect tcp://localhost:22` 和 `socketxp connect http://localhost:8080`；首先使用 portal token 对 agent 进行身份验证。<sup>[[2]](#references)</sup>

```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```

## Ngrok

ngrok 的 CLI 文档介绍了 HTTP 和 TCP 隧道。TCP 端点需要账户中预留一个 TCP 地址；免费套餐还要求提供有效的付款方式，FAQ 表示不会扣费。<sup>[[3]](#references)[[4]](#references)</sup>

```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```

## Telebit

旧版 Telebit.js CLI 帮助文档说明，`telebit http <port>` 用于 HTTPS 转发，`telebit tcp <local> [remote]` 用于原始 TCP；能否使用取决于部署方式和 relay。<sup>[[5]](#references)</sup>

```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```

## LocalXpose

LocalXpose 当前的网站记录了 `loclx tunnel http --to 3000` 命令，列出了对 HTTP/TLS/TCP/UDP 的支持，并说明免费计划适用于个人和轻度商业用途，而 TCP 隧道功能则属于付费计划。<sup>[[6]](#references)[[7]](#references)</sup>

```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```

## 暴露

Expose 文档介绍了适用于本地 HTTP/HTTPS URL 的 `expose share`，以及仅限 PRO 使用的 `expose share-port` 命令，可用于 TCP 端口。<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```

## Localtunnel

官方 localtunnel 仓库介绍了如何暴露 localhost 以进行测试，并记录了下面的 NPX 命令。<sup>[[10]](#references)</sup>

```bash
# Expose web in port 8000
npx localtunnel --port 8000
```

## Cloudflare Tunnel (cloudflared)

Cloudflare 当前文档介绍了用于本地开发的免认证“Quick”隧道，产品概览则列出了 HTTP、HTTPS、TCP、SSH 和 RDP 等支持发布的协议。<sup>[[11]](#references)[[12]](#references)</sup> 与 HTTP(S) 不同，发布的 TCP、SSH 和 RDP 路由无法通过普通客户端直接访问：Cloudflare 要求连接客户端安装 `cloudflared`，因此这些路由不符合本页面对原始 TCP 的免客户端安装要求。<sup>[[24]](#references)</sup>

对于本地管理的命名隧道，Cloudflare 记录了 `tunnel login`、`create`、`route dns` 和 `--config ... run ...` 的工作流程。<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```

Named tunnels 可以在 YAML 中定义多条 ingress 规则；Cloudflare Access policies 可控制对已发布应用的访问，Cloudflare 也记录了用于运行 connectors 的 service 和 Docker 部署方式。Quick Tunnels 是匿名的临时测试隧道，限制为 200 个并发请求，且不支持 Server-Sent Events (SSE)。<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

Tailscale 当前的 CLI 使用 Serve 在 tailnet 内共享，使用 Funnel 公开共享。这些命令支持将 HTTP/HTTPS 请求反向代理到目标，以及 TCP 转发；Funnel 的原始 TCP 模式仅限端口 443、8443 和 10000。<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```

使用 `--bg` 持久化配置，而无需保留前台进程；使用 `tailscale funnel status` 审核哪些服务可从公共互联网访问。对于 HTTPS Funnel 目标，Tailscale 文档说明，TLS 会在本地节点终止，然后再将请求转发到本地服务。<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp` 是一种自托管方案，你可以自行控制 rendezvous server（`frps`）和客户端（`frpc`）；其文档介绍了如何为 NAT 或防火墙后的本地服务配置转发，并指定确定的远程端口或域名。<sup>[[20]](#references)</sup>

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

当前项目文档包含 QUIC 传输、token/OIDC 身份验证、带宽限制、健康检查和 Go-template range 映射——使用这些选项前，请查阅与你部署版本相匹配的文档。<sup>[[20]](#references)</sup>

## Pinggy（基于 SSH）

Pinggy 文档介绍了通过端口 443 进行 SSH 反向转发，因此在出站 SSH 的 22 端口被屏蔽的网络中也可能可用。其免费方案在 60 分钟后会超时，重新连接后会使用新的 URL；Pro 方案则提供持久隧道和自定义域名。<sup>[[21]](#references)[[22]](#references)</sup>

```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```

You can request custom domains and persistent tunnels on Pro.<sup>[[22]](#references)</sup> You can recycle temporary tunnels automatically by wrapping the command in a loop.

## 威胁情报与 OPSEC 注意事项

攻击者曾滥用临时隧道，包括 Cloudflare 无需身份验证的 `trycloudflare.com` 端点，通过临时基础设施投递 Remote Access Trojans。Proofpoint 报告称，首次于 2024 年 2 月观察到相关活动，涉及 Xworm、AsyncRAT、VenomRAT、GuLoader 和 Remcos，并指出临时隧道会使依赖静态 blocklist 的防御措施更加复杂。<sup>[[23]](#references)</sup> 考虑主动轮换隧道和域名，并监控指向所用隧道工具的明显外部 DNS 查询，以便尽早发现蓝队检测或基础设施封锁尝试。

## References

- [1] [Serveo 文档](https://serveo.net/docs/)
- [2] [SocketXP 文档 - 入门指南](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [ngrok Agent 命令行界面](https://ngrok.com/docs/agent/cli)
- [4] [ngrok 常见问题](https://ngrok.com/docs/faq)
- [5] [Telebit.js 旧版 CLI 帮助](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [LocalXpose 文档](https://localxpose.gitbook.io/docs)
- [8] [Expose - 共享网站](https://expose.dev/docs/client/sharing)
- [9] [Expose - 共享 TCP 端口](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [localtunnel/localtunnel 仓库](https://github.com/localtunnel/localtunnel)
- [11] [Cloudflare 文档 - 设置 Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Cloudflare Tunnel 概述](https://developers.cloudflare.com/tunnel/)
- [13] [Cloudflare 文档 - 实用的隧道命令](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Cloudflare 文档 - 路由](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Cloudflare 文档 - 配置文件](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Cloudflare Access 策略](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Cloudflare 文档 - 运行参数](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Tailscale Serve 命令](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Tailscale Funnel 命令](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [fatedier/frp - Fast Reverse Proxy 仓库](https://github.com/fatedier/frp)
- [21] [Pinggy 文档 - 用法](https://pinggy.io/docs/usages/)
- [22] [Pinggy - 简易 localhost 隧道](https://pinggy.io/)
- [23] [Proofpoint - 威胁行为者滥用 Cloudflare Tunnels 投递 RAT](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
- [24] [Cloudflare 文档 - 隧道路由和支持的协议](https://developers.cloudflare.com/tunnel/concepts/routing/)
{{#include ../banners/hacktricks-training.md}}
