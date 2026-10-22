# Udostępnianie lokalnych usług w internecie

{{#include ../banners/hacktricks-training.md}}

**Celem tej strony jest przedstawienie alternatyw, które pozwalają udostępniać w internecie przynajmniej lokalne porty TCP oraz lokalne serwisy WWW (HTTP), bez konieczności instalowania czegokolwiek na drugim serwerze (instalacja może być potrzebna tylko lokalnie).**

## **Serveo**

Dokumentacja Serveo opisuje przekierowywanie SSH dla endpointów HTTP oraz prywatne/publiczne przekierowywanie TCP; żądanie publicznego portu TCP innego niż 80/443 (w tym portu 0, który przypisuje losowy port) wymaga zarejestrowanego konta użytkownika.<sup>[[1]](#references)</sup>

```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```

## SocketXP

Przewodnik SocketXP dla początkujących opisuje polecenia `socketxp connect tcp://localhost:22` i `socketxp connect http://localhost:8080`, które tworzą tunele TCP i HTTP; najpierw uwierzytelnia się agenta za pomocą tokenu portalu.<sup>[[2]](#references)</sup>

```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```

## Ngrok

CLI ngrok opisuje tunele HTTP i TCP; w FAQ podano, że punkty końcowe TCP w darmowym planie wymagają podania prawidłowej metody płatności, ale karta nie zostanie obciążona.<sup>[[3]](#references)[[4]](#references)</sup>

```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```

## Telebit

Dokumentacja CLI legacy Telebit.js opisuje `telebit http <port>` do przekierowywania HTTPS oraz `telebit tcp <local> [remote]` do surowego TCP; dostępność zależy od wdrożenia i relay.<sup>[[5]](#references)</sup>

```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```

## LocalXpose

Aktualna witryna LocalXpose opisuje polecenie `loclx tunnel http --to 3000`, wymienia obsługę HTTP/TLS/TCP/UDP i informuje, że bezpłatny plan obejmuje użytek osobisty i niewielki użytek komercyjny, a tunelowanie TCP jest dostępne w płatnym planie.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```

## Udostępnianie

Expose udostępnia dokumenty za pomocą `expose share` dla lokalnych adresów URL HTTP/HTTPS oraz komendy `expose share-port`, dostępnej wyłącznie w wersji PRO, dla portów TCP.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```

## Localtunnel

Oficjalne repozytorium localtunnel opisuje udostępnianie localhosta do testów i dokumentuje poniższe polecenie NPX.<sup>[[10]](#references)</sup>

```bash
# Expose web in port 8000
npx localtunnel --port 8000
```

## Cloudflare Tunnel (cloudflared)

Aktualna dokumentacja Cloudflare opisuje nieuwierzytelnione tunele „Quick” do lokalnego developmentu, a przegląd produktu wymienia HTTP, HTTPS, TCP, SSH i RDP wśród obsługiwanych protokołów publikowanych usług.<sup>[[11]](#references)[[12]](#references)</sup>

W przypadku lokalnie zarządzanego tunelu o nazwie Cloudflare opisuje workflow obejmujący `tunnel login`, `create`, `route dns` oraz `--config ... run ...`.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```

Nazwane tunele mogą definiować wiele reguł ingress w YAML; zasady Cloudflare Access mogą kontrolować dostęp do opublikowanych aplikacji, a Cloudflare opisuje sposoby wdrażania usług i Dockera do uruchamiania connectorów. Quick Tunnels to anonimowe, tymczasowe tunele testowe z limitem 200 równoczesnych żądań i bez obsługi Server-Sent Events (SSE).<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

Aktualne CLI Tailscale używa Serve do udostępniania wyłącznie w tailnecie, a Funnel do udostępniania publicznego. Polecenia obsługują cele reverse proxy HTTP/HTTPS i przekazywanie TCP; tryb raw TCP w Funnel jest ograniczony do portów 443, 8443 i 10000.<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```

Użyj `--bg`, aby zachować konfigurację bez utrzymywania procesu działającego na pierwszym planie, a polecenia `tailscale funnel status` użyj do sprawdzenia, które usługi są dostępne z publicznego internetu. W przypadku celów HTTPS Funnel Tailscale dokumentuje terminację TLS na lokalnym węźle przed przekazaniem żądania do lokalnej usługi.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp` to opcja hostowana samodzielnie, w której kontrolujesz serwer rendezvous (`frps`) i klienta (`frpc`); dokumentacja opisuje przekazywanie ruchu do lokalnych usług znajdujących się za NAT-em lub zaporą sieciową, z użyciem deterministycznych portów lub domen zdalnych.<sup>[[20]](#references)</sup>

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

Dokumentacja bieżącego projektu obejmuje transport QUIC, uwierzytelnianie tokenem/OIDC, limity przepustowości, kontrole stanu oraz mapowania range w Go-template — przed użyciem którejkolwiek z tych opcji sprawdź dokumentację wersji odpowiadającej wdrożeniu.<sup>[[20]](#references)</sup>

## Pinggy (oparte na SSH)

Pinggy opisuje tunelowanie zwrotne SSH przez port 443, dzięki czemu może działać w sieciach, w których wychodzący ruch SSH przez port 22 jest blokowany. W planie bezpłatnym połączenie jest rozłączane po 60 minutach, a po ponownym połączeniu używany jest nowy URL. Plan Pro zapewnia trwałe tunele i własne domeny.<sup>[[21]](#references)[[22]](#references)</sup>

```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```

Możesz zamówić własne domeny i trwałe tunele w planie Pro.<sup>[[22]](#references)</sup> Możesz automatycznie odnawiać tymczasowe tunele, umieszczając polecenie w pętli.

## Informacje o zagrożeniach i wskazówki OPSEC

Przeciwnicy nadużywali efemerycznego tunelowania, w tym nieuwierzytelnionych endpointów `trycloudflare.com` Cloudflare, aby dostarczać trojany zdalnego dostępu za pośrednictwem tymczasowej infrastruktury. Proofpoint poinformował o aktywności zaobserwowanej po raz pierwszy w lutym 2024 r., obejmującej Xworm, AsyncRAT, VenomRAT, GuLoader i Remcos, oraz zwrócił uwagę, że tymczasowe tunele utrudniają stosowanie zabezpieczeń opartych na statycznych listach blokowania.<sup>[[23]](#references)</sup> Rozważ proaktywne rotowanie tuneli i domen oraz monitoruj charakterystyczne zewnętrzne zapytania DNS do używanego narzędzia tunelującego, aby wcześnie wykrywać próby wykrycia przez blue team lub blokowania infrastruktury.

## References

- [1] [Dokumentacja Serveo](https://serveo.net/docs/)
- [2] [Dokumentacja SocketXP - Pierwsze kroki](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [Interfejs wiersza poleceń agenta ngrok](https://ngrok.com/docs/agent/cli)
- [4] [FAQ ngrok](https://ngrok.com/docs/faq)
- [5] [Pomoc starszego CLI Telebit.js](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [Dokumentacja LocalXpose](https://localxpose.gitbook.io/docs)
- [8] [Expose - Udostępnianie witryn](https://expose.dev/docs/client/sharing)
- [9] [Expose - Udostępnianie portów TCP](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [Repozytorium localtunnel/localtunnel](https://github.com/localtunnel/localtunnel)
- [11] [Dokumentacja Cloudflare - Konfigurowanie Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Przegląd Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [13] [Dokumentacja Cloudflare - Przydatne polecenia tunnel](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Dokumentacja Cloudflare - Routing](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Dokumentacja Cloudflare - Plik konfiguracyjny](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Zasady Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Dokumentacja Cloudflare - Parametry uruchamiania](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Polecenie Tailscale Serve](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Polecenie Tailscale Funnel](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [fatedier/frp - Repozytorium Fast Reverse Proxy](https://github.com/fatedier/frp)
- [21] [Dokumentacja Pinggy - Sposób użycia](https://pinggy.io/docs/usages/)
- [22] [Pinggy - Proste tunele localhost](https://pinggy.io/)
- [23] [Proofpoint - Aktor zagrożeń nadużywa Cloudflare Tunnels do dostarczania RAT-ów](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
{{#include ../banners/hacktricks-training.md}}
