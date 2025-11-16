# Udostępnianie lokalnych usług w internecie

{{#include ../../banners/hacktricks-training.md}}

**Celem tej strony jest zaproponowanie alternatyw, które pozwalają przynajmniej na wystawienie lokalnych surowych portów TCP oraz lokalnych stron (HTTP) do internetu BEZ konieczności instalowania czegokolwiek na drugim serwerze (tylko lokalnie, jeśli to konieczne).**

## **Serveo**

Z [https://serveo.net/](https://serveo.net/), umożliwia kilka funkcji przekierowywania HTTP i portów **za darmo**.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Dostępne pod [https://www.socketxp.com/download](https://www.socketxp.com/download), umożliwia wystawienie tcp i http:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

Z [https://ngrok.com/](https://ngrok.com/), umożliwia wystawienie portów http i tcp:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

Z [https://telebit.cloud/](https://telebit.cloud/) można wystawić porty http i tcp:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Według [https://localxpose.io/](https://localxpose.io/) oferuje kilka funkcji http i port forwarding **za darmo**.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

Z [https://expose.dev/](https://expose.dev/) można wystawić porty http i tcp:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

Z [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) umożliwia darmowe wystawienie HTTP:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Cloudflare's `cloudflared` CLI może tworzyć nieautoryzowane tunele "Quick" do szybkich demonstracji lub nazwane tunele powiązane z własną domeną/hostnames. Obsługuje HTTP(S) reverse proxies oraz raw TCP mappings trasowane przez Cloudflare's edge.
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
Nazwane tunele pozwalają zdefiniować wiele reguł ingress (HTTP, SSH, RDP itp.) w `tunnel.yml`, obsługują polityki dostępu dla poszczególnych usług za pośrednictwem Cloudflare Access i mogą działać jako kontenery systemd dla utrzymania trwałości. Szybkie tunele są anonimowe i efemeryczne — świetne do stagingu phishing payloadów lub testów webhook, ale Cloudflare nie gwarantuje dostępności.

## Tailscale Funnel / Serve

Tailscale v1.52+ dostarcza zunifikowane workflowy `tailscale serve` (share inside the tailnet) i `tailscale funnel` (publish to the wider internet). Oba polecenia mogą działać jako reverse proxy dla HTTP(S) lub przekazywać surowy TCP z automatycznym TLS i krótkimi nazwami hostów `*.ts.net`.
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Użyj `--bg`, aby zachować konfigurację bez utrzymywania procesu w pierwszym planie, oraz `tailscale funnel status`, aby sprawdzić, które usługi są osiągalne z publicznego internetu. Ponieważ Funnel terminuje TLS na lokalnym węźle, wszelkie monity o poświadczenia, nagłówki lub wymuszanie mTLS mogą pozostać pod twoją kontrolą.

## Fast Reverse Proxy (frp)

`frp` jest opcją self-hosted, w której kontrolujesz serwer rendezvous (`frps`) i klienta (`frpc`). To świetna opcja dla red teams, które już posiadają VPS i chcą mieć deterministyczne domeny/porty.

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

Najnowsze wydania dodają transport QUIC, token/OIDC auth, ograniczenia przepustowości, health checks oraz Go-template-based range mappings — przydatne do szybkiego uruchomienia wielu listeners, które mapują się z powrotem do implants na różnych hostach.

## Pinggy (SSH-based)

Pinggy udostępnia tunele dostępne przez SSH na TCP/443, więc działa nawet za captive proxies, które pozwalają jedynie na HTTPS. Sesje trwają 60 minut w free tier i można je skryptować dla szybkich demonstracji lub webhook relays.
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
Możesz zażądać niestandardowych domen i dłużej działających tuneli w płatnym planie, lub automatycznie odnawiać tunele, opakowując polecenie w pętlę.

## Informacje o zagrożeniach & notatki OPSEC

Złośliwi aktorzy coraz częściej nadużywają efemerycznych tuneli (zwłaszcza nieautoryzowanych endpointów Cloudflare `trycloudflare.com`) do umieszczania payloadów Remote Access Trojan i ukrywania infrastruktury C2. Proofpoint śledził kampanie od lutego 2024, które rozprowadzały AsyncRAT, Xworm, VenomRAT, GuLoader i Remcos, kierując etapy pobierania na krótkotrwałe adresy TryCloudflare, co sprawia, że tradycyjne statyczne listy blokujące są znacznie mniej skuteczne. Rozważ proaktywne rotowanie tuneli i domen, a także monitoruj charakterystyczne zewnętrzne zapytania DNS do tunelera, którego używasz, aby szybko wykryć próby detekcji przez blue-team lub blokowania infrastruktury.

## References

- [Cloudflare Docs - Create a locally-managed tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [Proofpoint - Threat Actor Abuses Cloudflare Tunnels to Deliver RATs](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)

{{#include ../../banners/hacktricks-training.md}}
