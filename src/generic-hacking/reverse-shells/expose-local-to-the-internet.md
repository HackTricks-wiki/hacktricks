# Udostępnianie lokalnych usług w internecie

{{#include ../../banners/hacktricks-training.md}}

**Celem tej strony jest przedstawienie alternatyw, które pozwalają co najmniej udostępniać lokalne porty raw TCP i lokalne strony WWW (HTTP) w internecie BEZ konieczności instalowania czegokolwiek na drugim serwerze (w razie potrzeby tylko lokalnie).**

## **Serveo**

Dokumentacja Serveo opisuje przekierowywanie SSH dla endpointów HTTP oraz prywatne/publiczne przekierowywanie TCP; żądanie niepublicznego portu TCP 80/443 (w tym portu 0 oznaczającego losowy port) wymaga zarejestrowanego użytkownika.<sup>[[1]](#references)</sup>
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Przewodnik getting-started SocketXP dokumentuje polecenia `socketxp connect tcp://localhost:22` i `socketxp connect http://localhost:8080` dla tuneli TCP i HTTP; agent jest najpierw uwierzytelniany za pomocą tokenu portalu.<sup>[[2]](#references)</sup>
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

CLI ngrok dokumentuje tunele HTTP i TCP; w FAQ podano, że TCP endpoints w darmowym planie wymagają prawidłowej metody płatności, a karta nie zostanie obciążona.<sup>[[3]](#references)[[4]](#references)</sup>
```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```
## Telebit

Dokumentacja pomocy legacy CLI Telebit.js opisuje `telebit http <port>` do przekierowywania HTTPS oraz `telebit tcp <local> [remote]` dla surowego TCP; dostępność zależy od wdrożenia i relay.<sup>[[5]](#references)</sup>
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Obecna strona LocalXpose opisuje polecenie `loclx tunnel http --to 3000`, wymienia obsługę HTTP/TLS/TCP/UDP oraz informuje, że darmowy plan obejmuje zastosowania osobiste i lekkie zastosowania komercyjne, podczas gdy tunelowanie TCP jest funkcją płatnego planu.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```
## Expose

Expose udostępnia dokumentację `expose share` dla lokalnych adresów URL HTTP/HTTPS oraz dostępną wyłącznie w PRO komendę `expose share-port` dla portów TCP.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```
## Localtunnel

Oficjalne repozytorium localtunnel opisuje udostępnianie localhost na potrzeby testów i dokumentuje poniższe polecenie NPX.<sup>[[10]](#references)</sup>
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Aktualna dokumentacja Cloudflare pokazuje nieuwierzytelnione tunele „Quick” do lokalnego developmentu, a przegląd produktu wymienia HTTP, HTTPS, TCP, SSH i RDP wśród obsługiwanych publikowanych protokołów.<sup>[[11]](#references)[[12]](#references)</sup>

W przypadku lokalnie zarządzanego nazwanego tunelu Cloudflare dokumentuje proces obejmujący `tunnel login`, `create`, `route dns` oraz `--config ... run ...`.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```
Named tunnels mogą definiować wiele reguł ingress w YAML; policies Cloudflare Access mogą kontrolować dostęp do opublikowanych applications, a Cloudflare dokumentuje ścieżki wdrażania service i Docker do uruchamiania connectorów. Quick Tunnels to anonimowe, tymczasowe tunnels do testów, z limitem 200 jednoczesnych requests i bez obsługi Server-Sent Events (SSE).<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

Obecny CLI Tailscale używa Serve do udostępniania wyłącznie w tailnet oraz Funnel do publicznego udostępniania. Commands obsługują cele HTTP/HTTPS reverse-proxy oraz TCP forwarding; raw TCP mode w Funnel jest ograniczony do ports 443, 8443 i 10000.<sup>[[18]](#references)[[19]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Użyj `--bg`, aby utrwalić konfigurację bez utrzymywania procesu na pierwszym planie, a następnie użyj `tailscale funnel status`, aby sprawdzić, które usługi są dostępne z publicznego internetu. W przypadku celów HTTPS Funnel Tailscale dokumentuje terminowanie TLS na lokalnym węźle przed przekazaniem żądania do lokalnej usługi.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp` to opcja self-hosted, w której kontrolujesz serwer rendezvous (`frps`) i klienta (`frpc`); dokumentacja obejmuje przekazywanie lokalnych usług znajdujących się za NAT-em lub firewallem, ze stałymi zdalnymi portami/domenami.<sup>[[20]](#references)</sup>

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

Aktualna dokumentacja projektu obejmuje transport QUIC, uwierzytelnianie tokenem/OIDC, limity przepustowości, kontrole stanu oraz mapowania zakresów Go-template — przed użyciem którejkolwiek z tych opcji sprawdź wydanie odpowiadające Twojemu wdrożeniu.<sup>[[20]](#references)</sup>

## Pinggy (SSH-based)

Pinggy opisuje SSH reverse forwarding przez port 443, dzięki czemu może działać w sieciach, w których wychodzący SSH na porcie 22 jest zablokowany. Jego darmowy plan wygasa po 60 minutach i po ponownym połączeniu używa nowego URL, natomiast Pro dodaje persistent tunnels oraz custom domains.<sup>[[21]](#references)[[22]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```
Możesz żądać niestandardowych domen i trwałych tuneli w planie Pro.<sup>[[22]](#references)</sup> Możesz automatycznie ponownie uruchamiać tymczasowe tunele, opakowując polecenie w pętlę.

## Notatki dotyczące threat intel i OPSEC

Adversaries wykorzystywali ephemeral tunneling, w tym nieuwierzytelnione endpointy `trycloudflare.com` Cloudflare, do dostarczania Remote Access Trojans za pośrednictwem tymczasowej infrastruktury. Proofpoint poinformował o aktywności zaobserwowanej po raz pierwszy w lutym 2024 roku, związanej z Xworm, AsyncRAT, VenomRAT, GuLoader i Remcos, oraz zauważył, że tymczasowe tunele komplikują obronę opartą na statycznych blocklistach.<sup>[[23]](#references)</sup> Rozważ proaktywną rotację tuneli i domen oraz monitoruj charakterystyczne zewnętrzne zapytania DNS do używanego tunnelera, aby wcześnie wykrywać detekcję przez blue-team lub próby blokowania infrastruktury.

## References

- [1] [Dokumentacja Serveo](https://serveo.net/docs/)
- [2] [Dokumentacja SocketXP - rozpoczęcie pracy](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [Interfejs wiersza poleceń ngrok Agent](https://ngrok.com/docs/agent/cli)
- [4] [FAQ ngrok](https://ngrok.com/docs/faq)
- [5] [Pomoc starszego CLI Telebit.js](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [Dokumentacja LocalXpose](https://localxpose.gitbook.io/docs)
- [8] [Expose - udostępnianie stron](https://expose.dev/docs/client/sharing)
- [9] [Expose - udostępnianie portów TCP](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [Repozytorium localtunnel/localtunnel](https://github.com/localtunnel/localtunnel)
- [11] [Cloudflare Docs - konfiguracja Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Przegląd Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [13] [Cloudflare Docs - przydatne polecenia tunnel](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Cloudflare Docs - routing](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Cloudflare Docs - plik konfiguracyjny](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Zasady Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Cloudflare Docs - parametry uruchamiania](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Polecenie Tailscale Serve](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Polecenie Tailscale Funnel](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [Repozytorium fatedier/frp - Fast Reverse Proxy](https://github.com/fatedier/frp)
- [21] [Dokumentacja Pinggy - użycie](https://pinggy.io/docs/usages/)
- [22] [Pinggy - proste tunele Localhost](https://pinggy.io/)
- [23] [Proofpoint - threat actor wykorzystuje Cloudflare Tunnels do dostarczania RAT-ów](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
{{#include ../../banners/hacktricks-training.md}}
