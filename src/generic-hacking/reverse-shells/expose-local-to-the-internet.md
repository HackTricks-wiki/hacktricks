# Опублікувати локальні сервіси в інтернет

{{#include ../../banners/hacktricks-training.md}}

**Метою цієї сторінки є запропонувати альтернативи, які щонайменше дозволяють експонувати локальні raw TCP-порти та локальні вебсервіси (HTTP) в інтернет без необхідності встановлювати щось на іншому сервері (тільки локально, якщо потрібно).**

## **Serveo**

На [https://serveo.net/](https://serveo.net/) доступні кілька можливостей переспрямування HTTP та портів **безкоштовно**.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

З [https://www.socketxp.com/download](https://www.socketxp.com/download), він дозволяє відкривати доступ до tcp та http:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

З [https://ngrok.com/](https://ngrok.com/) можна виставляти http та tcp порти:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

З [https://telebit.cloud/](https://telebit.cloud/) можна експонувати http і tcp порти:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

З [https://localxpose.io/](https://localxpose.io/) сервіс дозволяє кілька можливостей http та port forwarding **безкоштовно**.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

З [https://expose.dev/](https://expose.dev/) він дозволяє експонувати http та tcp порти:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

З [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) він дозволяє безкоштовно експонувати http:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

CLI `cloudflared` від Cloudflare може створювати неаутентифіковані «Quick» тунелі для швидких демонстрацій або іменовані тунелі, прив'язані до ваших власних доменів/hostnames. Він підтримує HTTP(S) reverse proxies, а також raw TCP mappings, що маршрутизуються через Cloudflare's edge.
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
Named tunnels дозволяють визначати кілька правил ingress (HTTP, SSH, RDP тощо) у `tunnel.yml`, підтримують політики доступу на рівні сервісу через Cloudflare Access і можуть запускатися як systemd-контейнери для persistence. Quick Tunnels анонімні та ефемерні — підходять для phishing payload staging або тестування webhook, але Cloudflare не гарантує uptime.

## Tailscale Funnel / Serve

Tailscale v1.52+ надає уніфіковані робочі процеси `tailscale serve` (share inside the tailnet) та `tailscale funnel` (publish to the wider internet). Обидві команди можуть reverse proxy HTTP(S) або forward raw TCP з автоматичним TLS та короткими `*.ts.net` hostnames.
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
<summary>Приклад конфігурації frps/frpc</summary>
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

Останні релізи додали QUIC transport, token/OIDC auth, обмеження пропускної здатності, health checks і Go-template-based range mappings — корисно для швидкого розгортання кількох listeners, які відображаються назад на implants на різних hosts.

## Pinggy (SSH-based)

Pinggy забезпечує SSH-accessible тунелі через TCP/443, тож він працює навіть за captive proxies, які дозволяють лише HTTPS. Сесії тривають 60 хвилин на безкоштовному тарифі й можуть бути автоматизовані для швидких демонстрацій або webhook relays.
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
Ви можете запросити власні домени та довше діючі тунелі на платному тарифі, або автоматично перезапускати тунелі, загорнувши команду в цикл.

## Розвідка загроз і зауваження щодо OPSEC

Зловмисники дедалі частіше зловживають тимчасовими тунелями (особливо неаутентифікованими кінцевими точками Cloudflare `trycloudflare.com`) для розгортання Remote Access Trojan payloads та приховування C2 інфраструктури. Proofpoint відстежував кампанії з лютого 2024 року, які поширювали AsyncRAT, Xworm, VenomRAT, GuLoader та Remcos, спрямовуючи етапи завантаження на короткоживучі TryCloudflare URL-адреси, що зробило традиційні статичні блоклісти значно менш ефективними. Розгляньте проактивну ротацію тунелів і доменів, а також моніторинг характерних зовнішніх DNS-запитів до tunneler'а, якого ви використовуєте, щоб вчасно помітити спроби виявлення з боку blue-team або блокування інфраструктури.

## References

- [Cloudflare Docs - Create a locally-managed tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [Proofpoint - Threat Actor Abuses Cloudflare Tunnels to Deliver RATs](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)

{{#include ../../banners/hacktricks-training.md}}
