# Udostępnianie lokalnych usług w internecie

{{#include ../banners/hacktricks-training.md}}

**Celem tej strony jest przedstawienie alternatyw, które pozwalają udostępnić w internecie CO NAJMNIEJ lokalne surowe porty TCP i lokalne strony WWW (HTTP), BEZ konieczności instalowania czegokolwiek na drugim serwerze (instalacja może być potrzebna tylko lokalnie).**

Aby przekazywać ruch między hostami, zamiast udostępniać usługę za pośrednictwem publicznego relay, zobacz [Tunneling and Port Forwarding](tunneling-and-port-forwarding.md).

## **Serveo**

Dokumentacja Serveo opisuje przekierowywanie SSH dla endpointów HTTP oraz prywatne i publiczne przekierowywanie TCP. Port `0` pozwala zażądać losowego publicznego portu TCP, nawet w sesjach anonimowych, ale takie sesje mają krótki czas trwania i ograniczenia połączeń; zażądanie wybranego publicznego portu TCP wymaga płatnego konta.<sup>[[1]](#references)</sup>

```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```

## SocketXP

Przewodnik SocketXP dla początkujących opisuje polecenia `socketxp connect tcp://localhost:22` i `socketxp connect http://localhost:8080` służące do tworzenia tuneli TCP i HTTP; najpierw agent uwierzytelnia się za pomocą tokena portalu.<sup>[[2]](#references)</sup>

```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```

## Ngrok

CLI ngrok dokumentuje tunele HTTP i TCP. Endpointy TCP wymagają zarezerwowanego adresu TCP na koncie; w darmowym planie wymagana jest również ważna metoda płatności, która — jak podaje FAQ — nie jest obciążana opłatami.<sup>[[3]](#references)[[4]](#references)</sup>

```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```

## Telebit

Starsza pomoc CLI Telebit.js opisuje `telebit http <port>` do przekierowywania HTTPS oraz `telebit tcp <local> [remote]` do surowego TCP; dostępność zależy od wdrożenia i relay.<sup>[[5]](#references)</sup>

```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```

## LocalXpose

Aktualna witryna LocalXpose dokumentuje polecenie `loclx tunnel http --to 3000`, wymienia obsługę HTTP/TLS/TCP/UDP i informuje, że bezpłatny plan obejmuje użytek osobisty i niewielki użytek komercyjny, a tunelowanie TCP jest dostępne w płatnym planie.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```

## Udostępnianie

Expose udostępnia lokalne adresy URL HTTP/HTTPS za pomocą polecenia `expose share` oraz porty TCP za pomocą polecenia `expose share-port`, dostępnego tylko w PRO.<sup>[[8]](#references)[[9]](#references)</sup>

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

Aktualna dokumentacja Cloudflare opisuje nieuwierzytelnione tunele „Quick” do lokalnego developmentu, a przegląd produktu wymienia HTTP, HTTPS, TCP, SSH i RDP wśród obsługiwanych publikowanych protokołów.<sup>[[11]](#references)[[12]](#references)</sup> W przeciwieństwie do HTTP(S), publikowane trasy TCP, SSH i RDP nie są bezpośrednio dostępne ze standardowego klienta: Cloudflare wymaga `cloudflared` na łączącym się kliencie, więc trasy te nie spełniają wymogu tej strony, aby do raw TCP nie trzeba było instalować klienta.<sup>[[24]](#references)</sup>

W przypadku lokalnie zarządzanego nazwanego tunelu Cloudflare opisuje workflow `tunnel login`, `create`, `route dns` oraz `--config ... run ...`.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```

Named tunnels mogą definiować wiele reguł ingress w YAML; zasady Cloudflare Access mogą kontrolować dostęp do opublikowanych aplikacji, a Cloudflare opisuje ścieżki wdrażania usług i Docker do uruchamiania connectorów. Quick Tunnels to anonimowe, tymczasowe tunele do testów, z limitem 200 równoczesnych żądań i bez obsługi Server-Sent Events (SSE).<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

Aktualne CLI Tailscale używa Serve do udostępniania wyłącznie w tailnecie, a Funnel do udostępniania publicznego. Polecenia obsługują cele reverse proxy HTTP/HTTPS i przekierowywanie TCP; tryb raw TCP w Funnel jest ograniczony do portów 443, 8443 i 10000.<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```

Użyj `--bg`, aby zachować konfigurację bez utrzymywania procesu działającego na pierwszym planie, i użyj `tailscale funnel status`, aby sprawdzić, które usługi są dostępne z publicznego internetu. W przypadku celów HTTPS Funnel Tailscale dokumentuje terminację TLS na lokalnym węźle przed przekazaniem żądania do usługi lokalnej.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp` to rozwiązanie hostowane samodzielnie, w którym kontrolujesz serwer rendezvous (`frps`) i klienta (`frpc`); dokumentacja opisuje przekazywanie lokalnych usług znajdujących się za NAT-em lub zaporą sieciową przy użyciu stałych portów i domen zdalnych.<sup>[[20]](#references)</sup>

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

Obecna dokumentacja projektu obejmuje transport QUIC, uwierzytelnianie tokenem/OIDC, limity przepustowości, kontrole stanu oraz mapowania zakresów Go-template — przed użyciem którejkolwiek z tych opcji sprawdź dokumentację wersji odpowiadającej Twojemu wdrożeniu.<sup>[[20]](#references)</sup>

## Pinggy (oparty na SSH)

Pinggy dokumentuje przekierowanie zwrotne SSH przez port 443, dzięki czemu może działać w sieciach, w których wychodzący ruch SSH przez port 22 jest blokowany. W bezpłatnym planie połączenie jest przerywane po 60 minutach, a po ponownym połączeniu używany jest nowy URL. Plan Pro oferuje trwałe tunele i własne domeny.<sup>[[21]](#references)[[22]](#references)</sup>

```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```

Możesz zamawiać niestandardowe domeny i trwałe tunele w planie Pro.<sup>[[22]](#references)</sup> Możesz automatycznie odnawiać tymczasowe tunele, umieszczając polecenie w pętli.

## Uwagi dotyczące threat intel i OPSEC

Adversaries nadużywali efemerycznego tunelowania, w tym nieuwierzytelnionych endpointów `trycloudflare.com` firmy Cloudflare, aby dostarczać Remote Access Trojans za pośrednictwem tymczasowej infrastruktury. Proofpoint poinformował o aktywności zaobserwowanej po raz pierwszy w lutym 2024 roku, obejmującej Xworm, AsyncRAT, VenomRAT, GuLoader i Remcos, oraz zwrócił uwagę, że tymczasowe tunele utrudniają obronę opartą na statycznych listach blokowanych elementów.<sup>[[23]](#references)</sup> Rozważ proaktywne rotowanie tuneli i domen oraz monitoruj charakterystyczne zewnętrzne zapytania DNS do używanego przez Ciebie tunelera, aby wcześnie wykryć próby wykrywania przez blue team lub blokowania infrastruktury.

## References

- [1] [Dokumentacja Serveo](https://serveo.net/docs/)
- [2] [Dokumentacja SocketXP - Pierwsze kroki](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [Interfejs wiersza poleceń ngrok Agent](https://ngrok.com/docs/agent/cli)
- [4] [Często zadawane pytania dotyczące ngrok](https://ngrok.com/docs/faq)
- [5] [Pomoc starszej wersji CLI Telebit.js](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [Dokumentacja LocalXpose](https://localxpose.gitbook.io/docs)
- [8] [Expose - Udostępnianie witryn](https://expose.dev/docs/client/sharing)
- [9] [Expose - Udostępnianie portów TCP](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [Repozytorium localtunnel/localtunnel](https://github.com/localtunnel/localtunnel)
- [11] [Dokumentacja Cloudflare - Konfigurowanie Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Omówienie Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [13] [Dokumentacja Cloudflare - Przydatne polecenia tunelu](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Dokumentacja Cloudflare - Routing](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Dokumentacja Cloudflare - Plik konfiguracyjny](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Zasady Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Dokumentacja Cloudflare - Parametry uruchomieniowe](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Polecenie Tailscale Serve](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Polecenie Tailscale Funnel](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [Repozytorium fatedier/frp - Fast Reverse Proxy](https://github.com/fatedier/frp)
- [21] [Dokumentacja Pinggy - Użycie](https://pinggy.io/docs/usages/)
- [22] [Pinggy - Proste tunele localhost](https://pinggy.io/)
- [23] [Proofpoint - Aktor zagrożeń nadużywa Cloudflare Tunnels do dostarczania RAT-ów](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
- [24] [Dokumentacja Cloudflare - Routing tuneli i obsługiwane protokoły](https://developers.cloudflare.com/tunnel/concepts/routing/)
{{#include ../banners/hacktricks-training.md}}
