# Expose local to the internet

{{#include ../../banners/hacktricks-training.md}}

**The goal of this page is to propose alternatives that allow AT LEAST to expose local raw TCP ports and local webs (HTTP) to the internet WITHOUT needing to install anything in the other server (only in local if needed).**

## **Serveo**

Serveo's documentation describes SSH forwarding for HTTP endpoints and private/public TCP forwarding; requesting a non-80/443 public TCP port (including port 0 for a random port) requires a registered user.<sup>[[1]](#references)</sup>

```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```

## SocketXP

SocketXP's getting-started guide documents `socketxp connect tcp://localhost:22` and `socketxp connect http://localhost:8080` for TCP and HTTP tunnels; the agent is authenticated with a portal token first.<sup>[[2]](#references)</sup>

```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```

## Ngrok

ngrok's CLI documents HTTP and TCP tunnels; its FAQ says free-tier TCP endpoints require a valid payment method and that the card is not charged.<sup>[[3]](#references)[[4]](#references)</sup>

```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```

## Telebit

The legacy Telebit.js CLI help documents `telebit http <port>` for HTTPS forwarding and `telebit tcp <local> [remote]` for raw TCP; availability depends on the deployment and relay.<sup>[[5]](#references)</sup>

```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```

## LocalXpose

LocalXpose's current site documents `loclx tunnel http --to 3000`, lists HTTP/TLS/TCP/UDP support, and says the free plan covers personal/light commercial use while TCP tunneling is a paid-plan capability.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```

## Expose

Expose documents `expose share` for HTTP/HTTPS local URLs and a PRO-only `expose share-port` command for TCP ports.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```

## Localtunnel

The official localtunnel repository describes exposing localhost for testing and documents the NPX command below.<sup>[[10]](#references)</sup>

```bash
# Expose web in port 8000
npx localtunnel --port 8000
```

## Cloudflare Tunnel (cloudflared)

Cloudflare's current docs show unauthenticated "Quick" tunnels for local development, and the product overview lists HTTP, HTTPS, TCP, SSH, and RDP among supported published protocols.<sup>[[11]](#references)[[12]](#references)</sup>

For a locally managed named tunnel, Cloudflare documents the `tunnel login`, `create`, `route dns`, and `--config ... run ...` workflow.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```

Named tunnels can define multiple ingress rules in YAML; Cloudflare Access policies can control access to published applications, and Cloudflare documents service and Docker deployment paths for running connectors. Quick Tunnels are anonymous, temporary testing tunnels with a 200-concurrent-request limit and no Server-Sent Events (SSE) support.<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

Tailscale's current CLI uses Serve for tailnet-only sharing and Funnel for public sharing. The commands support HTTP/HTTPS reverse-proxy targets and TCP forwarding; Funnel's raw TCP mode is limited to ports 443, 8443, and 10000.<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```

Use `--bg` to persist the configuration without keeping a foreground process, and use `tailscale funnel status` to audit what services are reachable from the public internet. For HTTPS Funnel targets, Tailscale documents TLS termination on the local node before forwarding the request to the local service.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp` is a self-hosted option where you control the rendezvous server (`frps`) and the client (`frpc`); its documentation covers forwarding local services behind NAT or a firewall with deterministic remote ports/domains.<sup>[[20]](#references)</sup>

<details>
<summary>Sample frps/frpc configuration</summary>

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

The current project documentation includes QUIC transport, token/OIDC authentication, bandwidth limits, health checks, and Go-template range mappings—consult the release matching your deployment before using any of those options.<sup>[[20]](#references)</sup>

## Pinggy (SSH-based)

Pinggy documents SSH reverse forwarding over port 443, so it can work in networks where outbound SSH on port 22 is blocked. Its free plan times out after 60 minutes and uses a new URL after reconnecting, while Pro adds persistent tunnels and custom domains.<sup>[[21]](#references)[[22]](#references)</sup>

```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```

You can request custom domains and persistent tunnels on Pro.<sup>[[22]](#references)</sup> You can recycle temporary tunnels automatically by wrapping the command in a loop.

## Threat intel & OPSEC notes

Adversaries have abused ephemeral tunneling, including Cloudflare's unauthenticated `trycloudflare.com` endpoints, to deliver Remote Access Trojans through temporary infrastructure. Proofpoint reported activity first observed in February 2024 involving Xworm, AsyncRAT, VenomRAT, GuLoader, and Remcos, and noted that temporary tunnels complicate defenses relying on static blocklists.<sup>[[23]](#references)</sup> Consider rotating tunnels and domains proactively, and monitor for telltale external DNS lookups to the tunneler you are using so you can spot blue-team detection or infrastructure blocking attempts early.

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
