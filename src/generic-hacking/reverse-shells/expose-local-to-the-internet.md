# Відкрити локальний доступ з інтернету

{{#include ../../banners/hacktricks-training.md}}

**Мета цієї сторінки — запропонувати альтернативи, які дозволяють ЩОНАЙМЕНШЕ відкрити локальні raw TCP-порти та локальні вебсервіси (HTTP) для доступу з інтернету БЕЗ потреби встановлювати щось на іншому сервері (за потреби — лише локально).**

## **Serveo**

На [https://serveo.net/](https://serveo.net/) доступні кілька функцій перенаправлення http і портів **безкоштовно**.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

На [https://www.socketxp.com/download](https://www.socketxp.com/download) можна зробити доступними tcp і http:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

З [https://ngrok.com/](https://ngrok.com/) можна відкрити доступ до http- і tcp-портів:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

На [https://telebit.cloud/](https://telebit.cloud/) можна відкрити доступ до http- і tcp-портів:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

На [https://localxpose.io/](https://localxpose.io/) доступні кілька функцій http і port forwarding **безкоштовно**.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

За допомогою [https://expose.dev/](https://expose.dev/) можна відкрити доступ до портів http і tcp:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

З [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) можна безкоштовно відкрити доступ до HTTP:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

CLI `cloudflared` від Cloudflare може створювати неавтентифіковані "Quick"-тунелі для швидких демонстрацій або іменовані тунелі, прив'язані до вашого домену/хостнеймів. Він підтримує reverse proxy для HTTP(S), а також raw TCP-мапінги, що маршрутизуються через edge Cloudflare.<sup>[[1]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
Іменовані тунелі дають змогу визначати кілька ingress rules (HTTP, SSH, RDP тощо) у `tunnel.yml`, застосовувати access policies для окремих сервісів через Cloudflare Access і запускати їх як systemd containers для persistence. Quick Tunnels є anonymous та ephemeral — чудово підходять для staging phishing payload або тестування webhook, але Cloudflare не гарантує uptime.<sup>[[1]](#references)</sup>

## Tailscale Funnel / Serve

У Tailscale v1.52+ доступні уніфіковані workflows `tailscale serve` (поширення всередині tailnet) і `tailscale funnel` (публікація у wider internet). Обидві команди можуть reverse proxy HTTP(S) або переспрямовувати raw TCP з automatic TLS і короткими hostnames `*.ts.net`.<sup>[[3]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Використовуйте `--bg`, щоб зберегти конфігурацію без запуску процесу у foreground, а `tailscale funnel status` — щоб перевірити, які сервіси доступні з публічного інтернету. Оскільки Funnel завершує TLS на локальному вузлі, усі запити облікових даних, заголовки або застосування mTLS можуть залишатися під вашим контролем.

## Fast Reverse Proxy (frp)

`frp` — це self-hosted варіант, у якому ви контролюєте сервер узгодження (`frps`) і клієнт (`frpc`). Він чудово підходить для red teams, які вже мають власний VPS і хочуть використовувати передбачувані домени/порти.

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

Останні релізи додають транспорт QUIC, token/OIDC auth, обмеження пропускної здатності, health checks і зіставлення діапазонів на основі Go templates — це корисно для швидкого запуску кількох listeners, які перенаправляють трафік до implants на різних хостах.<sup>[[4]](#references)</sup>

## Pinggy (на базі SSH)

Pinggy надає доступні через SSH тунелі поверх TCP/443, тому працює навіть за captive proxies, які дозволяють лише HTTPS. На безкоштовному рівні сесії тривають 60 хвилин, а їх можна використовувати у скриптах для швидких демонстрацій або relay webhook-повідомлень.<sup>[[5]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
Ви можете запитувати custom domains і довші тунелі на paid tier або автоматично перезапускати тунелі, обгорнувши команду в loop.

## Розвідка загроз та OPSEC

Зловмисники дедалі частіше зловживають ephemeral tunneling (особливо неавтентифікованими `trycloudflare.com` endpoints від Cloudflare), щоб розгортати payloads Remote Access Trojan і приховувати C2 infrastructure. Proofpoint відстежує кампанії з лютого 2024 року, у межах яких AsyncRAT, Xworm, VenomRAT, GuLoader і Remcos доставлялися через download stages, спрямовані на короткоживучі TryCloudflare URLs, що робило традиційні статичні blocklists значно менш ефективними. Розгляньте можливість проактивно ротувати тунелі та domains, а також відстежуйте характерні зовнішні DNS lookups до tunneler, який ви використовуєте, щоб завчасно виявляти blue-team detection або спроби блокування infrastructure.<sup>[[2]](#references)</sup>

## References

- [1] [Cloudflare Docs - Create a locally-managed tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [2] [Proofpoint - Threat Actor Abuses Cloudflare Tunnels to Deliver RATs](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
- [3] [Tailscale - Reintroducing Serve and Funnel](https://tailscale.com/blog/reintroducing-serve-funnel)
- [4] [fatedier/frp - Fast Reverse Proxy repository](https://github.com/fatedier/frp)
- [5] [Pinggy Documentation - Usage](https://pinggy.io/docs/usages/)

{{#include ../../banners/hacktricks-training.md}}
