# Udostępnianie lokalnych usług w internecie

**Celem tej strony jest przedstawienie alternatyw umożliwiających CO NAJMNIEJ udostępnianie lokalnych surowych portów TCP i lokalnych stron internetowych (HTTP) w internecie BEZ konieczności instalowania czegokolwiek na drugim serwerze (w razie potrzeby tylko lokalnie).**

## **Serveo**

Dokumentacja Serveo opisuje przekierowywanie SSH dla endpointów HTTP oraz prywatne/publiczne przekierowywanie TCP; żądanie publicznego portu TCP innego niż 80/443 (w tym portu 0 dla losowego portu) wymaga zarejestrowanego użytkownika.<sup>[[1]](#references)</sup>
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Przewodnik getting-started SocketXP opisuje polecenia `socketxp connect tcp://localhost:22` i `socketxp connect http://localhost:8080` dla tuneli TCP i HTTP; agent jest najpierw uwierzytelniany za pomocą tokenu portalu.<sup>[[2]](#references)</sup>
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

CLI ngrok dokumentuje tunele HTTP i TCP; jego FAQ informuje, że punkty końcowe TCP w bezpłatnym planie wymagają ważnej metody płatności i że karta nie zostanie obciążona.<sup>[[3]](#references)[[4]](#references)</sup>
```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```
## Telebit

Dokumentacja pomocy starszego CLI Telebit.js opisuje `telebit http <port>` do przekierowywania HTTPS oraz `telebit tcp <local> [remote]` do obsługi surowego TCP; dostępność zależy od wdrożenia i relay.<sup>[[5]](#references)</sup>
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Obecna strona LocalXpose opisuje polecenie `loclx tunnel http --to 3000`, wymienia obsługę HTTP/TLS/TCP/UDP oraz informuje, że bezpłatny plan obejmuje użytek osobisty i niewielki użytek komercyjny, natomiast tunelowanie TCP jest funkcją dostępną w płatnym planie.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```
## Expose

Expose udostępnia lokalne adresy URL HTTP/HTTPS za pomocą polecenia `expose share` oraz porty TCP za pomocą dostępnego tylko w PRO polecenia `expose share-port`.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```
## Localtunnel

Oficjalne repozytorium Localtunnel opisuje udostępnianie localhosta do testów i dokumentuje poniższe polecenie NPX.<sup>[[10]](#references)</sup>
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Aktualna dokumentacja Cloudflare pokazuje nieuwierzytelnione tunele „Quick” do lokalnego developmentu, a przegląd produktu wymienia HTTP, HTTPS, TCP, SSH i RDP wśród obsługiwanych publikowanych protokołów.<sup>[[11]](#references)[[12]](#references)</sup>

W przypadku zarządzanego lokalnie nazwanego tunelu Cloudflare dokumentuje workflow `tunnel login`, `create`, `route dns` oraz `--config ... run ...`.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```
Named tunnels mogą definiować wiele reguł ingress w YAML; policies Cloudflare Access mogą kontrolować dostęp do opublikowanych aplikacji, a Cloudflare dokumentuje ścieżki wdrażania service i Docker do uruchamiania connectorów. Quick Tunnels to anonimowe, tymczasowe tunele testowe z limitem 200 jednoczesnych żądań i bez obsługi Server-Sent Events (SSE).<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

Aktualne CLI Tailscale używa Serve do udostępniania wyłącznie w tailnecie oraz Funnel do udostępniania publicznego. Polecenia obsługują cele reverse-proxy HTTP/HTTPS i przekazywanie TCP; tryb raw TCP w Funnel jest ograniczony do portów 443, 8443 i 10000.<sup>[[18]](#references)[[19]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Use `--bg`, aby utrwalić konfigurację bez utrzymywania procesu na pierwszym planie, oraz `tailscale funnel status`, aby sprawdzić, które usługi są dostępne z publicznego internetu. W przypadku celów HTTPS Funnel Tailscale dokumentuje terminowanie TLS na lokalnym węźle przed przekazaniem żądania do lokalnej usługi.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp` to opcja self-hosted, w której kontrolujesz serwer rendezvous (`frps`) i klienta (`frpc`); dokumentacja obejmuje przekazywanie lokalnych usług znajdujących się za NAT-em lub firewallem z deterministycznymi zdalnymi portami/domenami.<sup>[[20]](#references)</sup>

<details>
<summary>Przykładowa konfiguracja frps/frpc</summary>
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

Obecna dokumentacja projektu obejmuje transport QUIC, uwierzytelnianie token/OIDC, limity przepustowości, testy stanu oraz mapowania zakresów Go-template — przed użyciem którejkolwiek z tych opcji zapoznaj się z wersją odpowiadającą Twojemu wdrożeniu.<sup>[[20]](#references)</sup>

## Pinggy (SSH-based)

Pinggy dokumentuje reverse forwarding SSH przez port 443, dzięki czemu może działać w sieciach, w których ruch wychodzący SSH przez port 22 jest zablokowany. Jego darmowy plan kończy działanie po 60 minutach i po ponownym połączeniu używa nowego URL, natomiast Pro dodaje persistent tunnels i niestandardowe domeny.<sup>[[21]](#references)[[22]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```
Możesz zamawiać custom domains i persistent tunnels w planie Pro.<sup>[[22]](#references)</sup> Możesz automatycznie odtwarzać temporary tunnels, umieszczając polecenie w pętli.

## Threat intel i notatki OPSEC

Adversaries wykorzystywali ephemeral tunneling, w tym nieuwierzytelnione endpointy `trycloudflare.com` Cloudflare, do dostarczania Remote Access Trojans za pośrednictwem temporary infrastructure. Proofpoint poinformował o aktywności zaobserwowanej po raz pierwszy w lutym 2024 r., obejmującej Xworm, AsyncRAT, VenomRAT, GuLoader i Remcos, oraz zauważył, że temporary tunnels komplikują obronę opartą na static blocklists.<sup>[[23]](#references)</sup> Rozważ proaktywną rotację tunnels i domains oraz monitoruj charakterystyczne zewnętrzne zapytania DNS do używanego tunnelera, aby wcześnie wykrywać działania blue teamu związane z detekcją lub próbami blokowania infrastruktury.

## References

- [1] [Dokumentacja Serveo](https://serveo.net/docs/)
- [2] [Dokumentacja SocketXP - rozpoczęcie pracy](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [Interfejs wiersza poleceń agenta ngrok](https://ngrok.com/docs/agent/cli)
- [4] [FAQ ngrok](https://ngrok.com/docs/faq)
- [5] [Pomoc starszego CLI Telebit.js](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [Dokumentacja LocalXpose](https://localxpose.gitbook.io/docs)
- [8] [Expose - udostępnianie sites](https://expose.dev/docs/client/sharing)
- [9] [Expose - udostępnianie portów TCP](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [repozytorium localtunnel/localtunnel](https://github.com/localtunnel/localtunnel)
- [11] [Dokumentacja Cloudflare - konfiguracja Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Przegląd Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [13] [Dokumentacja Cloudflare - przydatne polecenia tunnel](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Dokumentacja Cloudflare - routing](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Dokumentacja Cloudflare - plik konfiguracyjny](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Zasady Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Dokumentacja Cloudflare - parametry uruchamiania](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Polecenie Serve Tailscale](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Polecenie Funnel Tailscale](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [repozytorium fatedier/frp - Fast Reverse Proxy](https://github.com/fatedier/frp)
- [21] [Dokumentacja Pinggy - użycie](https://pinggy.io/docs/usages/)
- [22] [Pinggy - proste tunnels dla localhost](https://pinggy.io/)
- [23] [Proofpoint - threat actor wykorzystuje Cloudflare Tunnels do dostarczania RAT-ów](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
{{#include ../../banners/hacktricks-training.md}}
