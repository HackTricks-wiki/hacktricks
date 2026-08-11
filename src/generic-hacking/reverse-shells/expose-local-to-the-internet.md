# Відкрити локальний доступ до інтернету

**Мета цієї сторінки — запропонувати альтернативи, які дають змогу принаймні відкрити локальні raw TCP-порти та локальні вебсайти (HTTP) для доступу з інтернету БЕЗ необхідності щось встановлювати на іншому сервері (лише локально, якщо це потрібно).**

## **Serveo**

Документація Serveo описує SSH forwarding для HTTP endpoints і приватного/публічного TCP forwarding; запит непублічного TCP-порту 80/443 (зокрема порту 0 для випадкового порту) вимагає зареєстрованого користувача.<sup>[[1]](#references)</sup>
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

У посібнику SocketXP для початку роботи описано `socketxp connect tcp://localhost:22` і `socketxp connect http://localhost:8080` для TCP- і HTTP-тунелів; спочатку agent автентифікується за допомогою portal token.<sup>[[2]](#references)</sup>
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

CLI ngrok документує HTTP- і TCP-тунелі; у його FAQ зазначено, що TCP endpoints у free tier потребують дійсного способу оплати, а картка не буде стягуватися.<sup>[[3]](#references)[[4]](#references)</sup>
```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```
## Telebit

Застаріла довідка CLI Telebit.js документує `telebit http <port>` для перенаправлення HTTPS і `telebit tcp <local> [remote]` для необробленого TCP; доступність залежить від розгортання та relay.<sup>[[5]](#references)</sup>
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

На поточному сайті LocalXpose описано команду `loclx tunnel http --to 3000`, зазначено підтримку HTTP/TLS/TCP/UDP і вказано, що безкоштовний план призначений для особистого та легкого комерційного використання, тоді як тунелювання TCP доступне лише в платному плані.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```
## Expose

У документації Expose описано `expose share` для локальних URL-адрес HTTP/HTTPS і команду `expose share-port`, доступну лише в PRO, для TCP-портів.<sup>[[8]](#references)[[9]](#references)</sup>
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

Поточна документація Cloudflare описує неавтентифіковані «Quick» tunnels для локальної розробки, а в огляді продукту серед підтримуваних опублікованих протоколів зазначено HTTP, HTTPS, TCP, SSH і RDP.<sup>[[11]](#references)[[12]](#references)</sup>

Для керованого локально іменованого тунелю Cloudflare документує workflow `tunnel login`, `create`, `route dns` і `--config ... run ...`.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```
Іменовані тунелі можуть визначати кілька правил ingress у YAML; політики Cloudflare Access можуть контролювати доступ до опублікованих застосунків, а Cloudflare документує способи розгортання сервісів і Docker для запуску конекторів. Quick Tunnels — це анонімні тимчасові тунелі для тестування з обмеженням у 200 одночасних запитів і без підтримки Server-Sent Events (SSE).<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

Поточний CLI Tailscale використовує Serve для спільного доступу лише в межах tailnet, а Funnel — для публічного доступу. Команди підтримують цілі reverse-proxy для HTTP/HTTPS і перенаправлення TCP; режим Funnel для необробленого TCP обмежений портами 443, 8443 і 10000.<sup>[[18]](#references)[[19]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Використовуйте `--bg`, щоб зберегти конфігурацію без підтримання процесу у foreground, а `tailscale funnel status` — щоб перевірити, які сервіси доступні з публічного інтернету. Для цілей HTTPS Funnel Tailscale документує завершення TLS на локальному вузлі перед перенаправленням запиту до локального сервісу.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp` — це self-hosted варіант, у якому ви контролюєте rendezvous-сервер (`frps`) і клієнт (`frpc`); його документація описує перенаправлення локальних сервісів, розташованих за NAT або firewall, із детермінованими віддаленими портами/доменами.<sup>[[20]](#references)</sup>

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

Поточна документація проєкту містить транспорт QUIC, автентифікацію за допомогою token/OIDC, обмеження пропускної здатності, health checks і зіставлення range у Go-template — перед використанням будь-якої з цих опцій ознайомтеся з релізом, що відповідає вашому розгортанню.<sup>[[20]](#references)</sup>

## Pinggy (на основі SSH)

Pinggy документує SSH reverse forwarding через порт 443, тому він може працювати в мережах, де вихідний SSH через порт 22 заблоковано. Термін дії його free plan спливає через 60 хвилин, а після повторного підключення використовується новий URL; Pro додає persistent tunnels і custom domains.<sup>[[21]](#references)[[22]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```
На Pro можна запитувати custom domains і persistent tunnels.<sup>[[22]](#references)</sup> Тимчасові tunnels можна автоматично перевикористовувати, обгорнувши команду в loop.

## Threat intel & OPSEC notes

Adversaries зловживали ephemeral tunneling, зокрема неавтентифікованими endpoints Cloudflare `trycloudflare.com`, щоб доставляти Remote Access Trojans через тимчасову інфраструктуру. Proofpoint повідомила про активність, уперше зафіксовану в лютому 2024 року, пов'язану з Xworm, AsyncRAT, VenomRAT, GuLoader і Remcos, і зазначила, що тимчасові tunnels ускладнюють захист, який покладається на статичні blocklists.<sup>[[23]](#references)</sup> Розгляньте можливість проактивної ротації tunnels і domains та моніторте характерні зовнішні DNS-запити до tunneler, який ви використовуєте, щоб завчасно виявляти detection з боку blue-team або спроби блокування інфраструктури.

## References

- [1] [Документація Serveo](https://serveo.net/docs/)
- [2] [Документація SocketXP - Початок роботи](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [Інтерфейс командного рядка ngrok Agent](https://ngrok.com/docs/agent/cli)
- [4] [FAQ ngrok](https://ngrok.com/docs/faq)
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
- [22] [Pinggy - Прості localhost tunnels](https://pinggy.io/)
- [23] [Proofpoint - Threat Actor зловживає Cloudflare Tunnels для доставки RATs](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
{{#include ../../banners/hacktricks-training.md}}
