# Expose local to the internet

{{#include ../../banners/hacktricks-training.md}}

**The goal of this page is to propose alternatives that allow AT LEAST to expose local raw TCP ports and local webs (HTTP) to the internet WITHOUT needing to install anything in the other server (only in local if needed).**

## **Serveo**

From [https://serveo.net/](https://serveo.net/), it allows several http and port forwarding features **for free**.

```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```

## SocketXP

From [https://www.socketxp.com/download](https://www.socketxp.com/download), it allows to expose tcp and http:

```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```

## Ngrok

From [https://ngrok.com/](https://ngrok.com/), it allows to expose http and tcp ports:

```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```

## Telebit

From [https://telebit.cloud/](https://telebit.cloud/) it allows to expose http and tcp ports:

```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```

## LocalXpose

From [https://localxpose.io/](https://localxpose.io/), it allows several http and port forwarding features **for free**.

```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```

## Expose

From [https://expose.dev/](https://expose.dev/) it allows to expose http and tcp ports:

```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```

## Localtunnel

From [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) it allows to expose http for free:

```bash
# Expose web in port 8000
npx localtunnel --port 8000
```

## Cloudflare Tunnel (cloudflared)

Cloudflare's `cloudflared` CLI can create unauthenticated "Quick" tunnels for fast demos or named tunnels bound to your own domain/hostnames. It supports HTTP(S) reverse proxies as well as raw TCP mappings routed through Cloudflare's edge.

```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```

Named tunnels let you define multiple ingress rules (HTTP, SSH, RDP, etc.) inside `tunnel.yml`, support per-service access policies via Cloudflare Access, and can run as systemd containers for persistence. Quick Tunnels are anonymous and ephemeral—great for phishing payload staging or webhook tests, but Cloudflare does not guarantee uptime.

## Tailscale Funnel / Serve

Tailscale v1.52+ ships unified `tailscale serve` (share inside the tailnet) and `tailscale funnel` (publish to the wider internet) workflows. Both commands can reverse proxy HTTP(S) or forward raw TCP with automatic TLS and short `*.ts.net` hostnames.

```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```

Use `--bg` to persist the configuration without keeping a foreground process, and `tailscale funnel status` to audit what services are reachable from the public internet. Because Funnel terminates TLS on the local node, any credential prompts, headers, or mTLS enforcement can stay under your control.

## Fast Reverse Proxy (frp)

`frp` is a self-hosted option where you control the rendezvous server (`frps`) and the client (`frpc`). It is great for red teams that already own a VPS and want deterministic domains/ports.

<details>
<summary>Sample frps/frpc configuration</summary>

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

Recent releases add QUIC transport, token/OIDC auth, bandwidth caps, health checks, and Go-template-based range mappings—useful for quickly standing up multiple listeners that map back to implants on different hosts.

## Pinggy (SSH-based)

Pinggy provides SSH-accessible tunnels over TCP/443, so it works even behind captive proxies that only allow HTTPS. Sessions last 60 minutes on the free tier and can be scripted for quick demos or webhook relays.

```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```

You can request custom domains and longer-lived tunnels on the paid tier, or recycle tunnels automatically by wrapping the command in a loop.

## Threat intel & OPSEC notes

Adversaries have increasingly abused ephemeral tunneling (especially Cloudflare's unauthenticated `trycloudflare.com` endpoints) to stage Remote Access Trojan payloads and hide C2 infrastructure. Proofpoint tracked campaigns since February 2024 that pushed AsyncRAT, Xworm, VenomRAT, GuLoader, and Remcos by pointing download stages to short-lived TryCloudflare URLs, making traditional static blocklists far less effective. Consider rotating tunnels and domains proactively, but also monitor for telltale external DNS lookups to the tunneler you are using so you can spot blue-team detection or infrastructure blocking attempts early.

## References

- [Cloudflare Docs - Create a locally-managed tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [Proofpoint - Threat Actor Abuses Cloudflare Tunnels to Deliver RATs](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)

{{#include ../../banners/hacktricks-training.md}}
