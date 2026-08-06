# Udostępnianie lokalnych usług w internecie

{{#include ../../banners/hacktricks-training.md}}

**Celem tej strony jest przedstawienie alternatyw umożliwiających co najmniej udostępnianie lokalnych portów raw TCP i lokalnych stron web (HTTP) w internecie BEZ konieczności instalowania czegokolwiek na drugim serwerze (jeśli jest to potrzebne, instalacja odbywa się tylko lokalnie).**

## **Serveo**

Z [https://serveo.net/](https://serveo.net/) można bezpłatnie korzystać z kilku funkcji związanych z HTTP i przekierowywaniem portów.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Ze strony [https://www.socketxp.com/download](https://www.socketxp.com/download) umożliwia wystawienie tcp i http:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

Z [https://ngrok.com/](https://ngrok.com/) można wystawiać porty http i tcp:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

Z [https://telebit.cloud/](https://telebit.cloud/) można wystawiać porty http i tcp:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

[https://localxpose.io/](https://localxpose.io/) umożliwia korzystanie z kilku funkcji przekierowywania HTTP i portów **bezpłatnie**.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

Z [https://expose.dev/](https://expose.dev/) można udostępniać porty http i tcp:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

Z [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) można bezpłatnie udostępnić http:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

CLI `cloudflared` firmy Cloudflare może tworzyć nieuwierzytelnione tunele „Quick” do szybkich demonstracji lub nazwane tunele powiązane z własną domeną/nazwami hostów. Obsługuje odwrotne proxy HTTP(S), a także mapowania surowego TCP routowane przez edge Cloudflare.<sup>[[1]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
Named tunnels pozwalają definiować wiele reguł ingress (HTTP, SSH, RDP itd.) w pliku `tunnel.yml`, obsługują zasady dostępu dla poszczególnych usług za pośrednictwem Cloudflare Access i mogą działać jako kontenery systemd, zapewniając trwałość. Quick Tunnels są anonimowe i efemeryczne — świetnie nadają się do stagingu phishing payloadów lub testów webhooków, ale Cloudflare nie gwarantuje ich dostępności.<sup>[[1]](#references)</sup>

## Tailscale Funnel / Serve

Tailscale v1.52+ udostępnia ujednolicone workflow `tailscale serve` (udostępnianie wewnątrz tailnetu) i `tailscale funnel` (publikowanie w szerszym internecie). Oba polecenia mogą pełnić funkcję reverse proxy dla HTTP(S) lub przekazywać surowy TCP, zapewniając automatyczny TLS i krótkie hostnames `*.ts.net`.<sup>[[3]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Użyj `--bg`, aby utrwalić konfigurację bez utrzymywania procesu na pierwszym planie, oraz `tailscale funnel status`, aby sprawdzić, które usługi są dostępne z publicznego Internetu. Ponieważ Funnel kończy TLS na lokalnym węźle, wszelkie monity o dane uwierzytelniające, nagłówki lub egzekwowanie mTLS mogą pozostać pod Twoją kontrolą.

## Fast Reverse Proxy (frp)

`frp` to opcja self-hosted, w której kontrolujesz serwer rendezvous (`frps`) i klienta (`frpc`). Doskonale sprawdza się w przypadku red teams, które mają już VPS i chcą korzystać z deterministycznych domen/portów.

<details>
<summary>Przykładowa konfiguracja frps/frpc</summary>
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

Nowsze wydania dodają transport QUIC, uwierzytelnianie token/OIDC, limity przepustowości, kontrole stanu oraz mapowania zakresów oparte na Go templates — przydatne do szybkiego uruchamiania wielu listenerów mapujących połączenia z implantami na różnych hostach.<sup>[[4]](#references)</sup>

## Pinggy (oparte na SSH)

Pinggy udostępnia dostępne przez SSH tunele przez TCP/443, dzięki czemu działa nawet za captive proxies, które zezwalają wyłącznie na HTTPS. Sesje w darmowym planie trwają 60 minut i można je skryptować na potrzeby szybkich demonstracji lub relayów webhooków.<sup>[[5]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
You can request custom domains and longer-lived tunnels on the paid tier, or recycle tunnels automatically by wrapping the command in a loop.

## Uwagi dotyczące threat intel i OPSEC

Adversaries have increasingly abused ephemeral tunneling (especially Cloudflare's unauthenticated `trycloudflare.com` endpoints) to stage Remote Access Trojan payloads and hide C2 infrastructure. Proofpoint tracked campaigns since February 2024 that pushed AsyncRAT, Xworm, VenomRAT, GuLoader, and Remcos by pointing download stages to short-lived TryCloudflare URLs, making traditional static blocklists far less effective. Rozważ proaktywne rotowanie tunnels i domains, ale monitoruj również charakterystyczne zewnętrzne zapytania DNS do używanego tunneler, aby wcześnie wykrywać detekcję przez blue team lub próby blokowania infrastruktury.<sup>[[2]](#references)</sup>

## References

- [1] [Cloudflare Docs - Tworzenie tunnel zarządzanego lokalnie](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [2] [Proofpoint - Threat actor nadużywa Cloudflare Tunnels do dostarczania RAT](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
- [3] [Tailscale - Ponowne wprowadzenie Serve i Funnel](https://tailscale.com/blog/reintroducing-serve-funnel)
- [4] [fatedier/frp - Repozytorium Fast Reverse Proxy](https://github.com/fatedier/frp)
- [5] [Pinggy Documentation - Użycie](https://pinggy.io/docs/usages/)

{{#include ../../banners/hacktricks-training.md}}
