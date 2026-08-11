# Відкрити локальний доступ до інтернету

{{#include ../../banners/hacktricks-training.md}}

**Мета цієї сторінки — запропонувати альтернативи, які дають змогу ЩОНАЙМЕНШЕ відкрити локальні raw TCP-порти та локальні вебсайти (HTTP) для доступу з інтернету БЕЗ необхідності встановлювати щось на іншому сервері (лише локально, якщо потрібно).**

## **Serveo**

Документація Serveo описує SSH forwarding для HTTP endpoints і приватного/публічного TCP forwarding; запит непублічного TCP-порту 80/443 (включно з портом 0 для випадкового порту) потребує зареєстрованого користувача.<sup>[[1]](#references)</sup>
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

У посібнику SocketXP для початку роботи описано команди `socketxp connect tcp://localhost:22` і `socketxp connect http://localhost:8080` для TCP- та HTTP-тунелів; спочатку агент автентифікується за допомогою токена порталу.<sup>[[2]](#references)</sup>
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

CLI ngrok документує HTTP- і TCP-тунелі; у його FAQ зазначено, що TCP endpoints на безкоштовному тарифі потребують дійсного способу оплати, а кошти з картки не списуються.<sup>[[3]](#references)[[4]](#references)</sup>
```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```
## Telebit

Застаріла документація CLI Telebit.js описує `telebit http <port>` для переспрямування HTTPS і `telebit tcp <local> [remote]` для необробленого TCP; доступність залежить від розгортання та relay.<sup>[[5]](#references)</sup>
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

На поточному сайті LocalXpose описано `loclx tunnel http --to 3000`, зазначено підтримку HTTP/TLS/TCP/UDP, а також вказано, що free plan охоплює особисте та легке комерційне використання, тоді як tunneling TCP доступний у платному плані.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```
## Expose

Expose документує `expose share` для локальних URL HTTP/HTTPS і доступну лише в PRO команду `expose share-port` для TCP-портів.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```
## Localtunnel

Офіційний репозиторій localtunnel описує відкриття localhost для тестування та документує наведену нижче команду NPX.<sup>[[10]](#references)</sup>
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Поточна документація Cloudflare описує неавтентифіковані "Quick" tunnels для локальної розробки, а в огляді продукту серед підтримуваних для публікації протоколів зазначено HTTP, HTTPS, TCP, SSH і RDP.<sup>[[11]](#references)[[12]](#references)</sup>

Для локально керованого іменованого tunnel Cloudflare документує процес із використанням `tunnel login`, `create`, `route dns` і `--config ... run ...`.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```
Іменовані тунелі можуть визначати кілька ingress-правил у YAML; політики Cloudflare Access можуть контролювати доступ до опублікованих застосунків, а Cloudflare документує способи розгортання service і Docker для запуску конекторів. Quick Tunnels — це анонімні тимчасові тунелі для тестування з обмеженням у 200 одночасних запитів і без підтримки Server-Sent Events (SSE).<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

Поточний CLI Tailscale використовує Serve для спільного доступу лише в межах tailnet, а Funnel — для публічного доступу. Команди підтримують цілі reverse proxy для HTTP/HTTPS і TCP forwarding; raw TCP mode у Funnel обмежений портами 443, 8443 і 10000.<sup>[[18]](#references)[[19]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Use `--bg`, щоб зберегти конфігурацію без підтримання процесу у foreground, а `tailscale funnel status` — щоб перевірити, які сервіси доступні з публічного інтернету. Для цілей HTTPS Funnel Tailscale документує завершення TLS на локальному вузлі перед перенаправленням запиту до локального сервісу.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp` — це self-hosted опція, у якій ви контролюєте rendezvous-сервер (`frps`) і клієнт (`frpc`); його документація охоплює перенаправлення локальних сервісів за NAT або firewall із детермінованими віддаленими портами/доменами.<sup>[[20]](#references)</sup>

<details>
<summary>Приклад конфігурації frps/frpc</summary>
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

Поточна документація проєкту включає транспорт QUIC, автентифікацію token/OIDC, обмеження пропускної здатності, health checks і відображення діапазонів Go-template — перед використанням будь-яких із цих параметрів ознайомтеся з релізом, що відповідає вашому розгортанню.<sup>[[20]](#references)</sup>

## Pinggy (на основі SSH)

У документації Pinggy описано reverse forwarding SSH через порт 443, тому він може працювати в мережах, де вихідні SSH-з’єднання через порт 22 заблоковані. У безкоштовному плані з’єднання переривається через 60 хвилин, а після повторного підключення використовується новий URL; Pro додає постійні тунелі та custom domains.<sup>[[21]](#references)[[22]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```
Ви можете запитувати custom domains і persistent tunnels на Pro.<sup>[[22]](#references)</sup> Ви можете автоматично повторно використовувати тимчасові tunnels, обгорнувши команду в loop.

## Нотатки щодо Threat intel та OPSEC

Adversaries зловживали ephemeral tunneling, зокрема неавтентифікованими endpoints Cloudflare `trycloudflare.com`, щоб доставляти Remote Access Trojans через тимчасову інфраструктуру. Proofpoint повідомила про активність, уперше виявлену в лютому 2024 року, пов'язану з Xworm, AsyncRAT, VenomRAT, GuLoader і Remcos, і зазначила, що тимчасові tunnels ускладнюють захист, який покладається на статичні blocklists.<sup>[[23]](#references)</sup> Розгляньте можливість проактивної ротації tunnels і domains, а також моніторте характерні зовнішні DNS-запити до tunneler, який ви використовуєте, щоб завчасно виявляти detection з боку blue-team або спроби блокування інфраструктури.

## References

- [1] [Документація Serveo](https://serveo.net/docs/)
- [2] [Документація SocketXP - Початок роботи](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [Інтерфейс командного рядка агента ngrok](https://ngrok.com/docs/agent/cli)
- [4] [Поширені запитання ngrok](https://ngrok.com/docs/faq)
- [5] [Довідка legacy CLI Telebit.js](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [Документація LocalXpose](https://localxpose.gitbook.io/docs)
- [8] [Expose - Поширення сайтів](https://expose.dev/docs/client/sharing)
- [9] [Expose - Поширення TCP-портів](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [Репозиторій localtunnel/localtunnel](https://github.com/localtunnel/localtunnel)
- [11] [Документація Cloudflare - Налаштування Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Огляд Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [13] [Документація Cloudflare - Корисні команди tunnel](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Документація Cloudflare - Маршрутизація](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Документація Cloudflare - Файл конфігурації](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Політики Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Документація Cloudflare - Параметри запуску](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Команда Tailscale Serve](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Команда Tailscale Funnel](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [Репозиторій fatedier/frp - Fast Reverse Proxy](https://github.com/fatedier/frp)
- [21] [Документація Pinggy - Використання](https://pinggy.io/docs/usages/)
- [22] [Pinggy - Прості tunnels для localhost](https://pinggy.io/)
- [23] [Proofpoint - Threat actor зловживає Cloudflare Tunnels для доставки RATs](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
{{#include ../../banners/hacktricks-training.md}}
