# Izložite lokalni servis na internetu

{{#include ../banners/hacktricks-training.md}}

**Cilj ove stranice je da predloži alternative koje omogućavaju da se lokalni raw TCP portovi i lokalne web-aplikacije (HTTP) izlože na internetu, BEZ potrebe da se bilo šta instalira na drugom serveru (samo lokalno, ako je potrebno).**

Za prosleđivanje između hostova, umesto objavljivanja servisa preko javnog releja, pogledajte [Tunneling and Port Forwarding](tunneling-and-port-forwarding.md).

## **Serveo**

Serveo dokumentacija opisuje SSH prosleđivanje za HTTP krajnje tačke i privatno/javno TCP prosleđivanje. Port `0` traži nasumični javni TCP port, čak i za anonimne sesije, ali takve sesije imaju kratko trajanje i ograničen broj konekcija; zahtev za određenim javnim TCP portom zahteva plaćeni nalog.<sup>[[1]](#references)</sup>

```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```

## SocketXP

SocketXP-ov vodič za početak dokumentuje `socketxp connect tcp://localhost:22` i `socketxp connect http://localhost:8080` za TCP i HTTP tunele; agent se prvo autentifikuje pomoću portal tokena.<sup>[[2]](#references)</sup>

```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```

## Ngrok

CLI alat ngrok dokumentuje HTTP i TCP tunele. TCP endpointi zahtevaju rezervisanu TCP adresu na nalogu; za besplatni paket je potreban i važeći način plaćanja, za koji FAQ navodi da se ne naplaćuje.<sup>[[3]](#references)[[4]](#references)</sup>

```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```

## Telebit

Nasleđena Telebit.js CLI pomoć dokumentuje `telebit http <port>` za prosleđivanje HTTPS saobraćaja i `telebit tcp <local> [remote]` za sirovi TCP; dostupnost zavisi od deploymenta i relay-a.<sup>[[5]](#references)</sup>

```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```

## LocalXpose

Na aktuelnom sajtu LocalXpose-a navedena je komanda `loclx tunnel http --to 3000`, podrška za HTTP/TLS/TCP/UDP i informacija da besplatni plan pokriva ličnu i ograničenu komercijalnu upotrebu, dok je TCP tunneling dostupan samo uz plaćeni plan.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```

## Expose

Expose dokumentuje `expose share` za lokalne HTTP/HTTPS URL-ove i komandu `expose share-port`, dostupnu samo u PRO verziji, za TCP portove.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```

## Localtunnel

Zvanični localtunnel repozitorijum opisuje izlaganje localhost-a radi testiranja i dokumentuje NPX komandu u nastavku.<sup>[[10]](#references)</sup>

```bash
# Expose web in port 8000
npx localtunnel --port 8000
```

## Cloudflare Tunnel (cloudflared)

Aktuelna Cloudflare dokumentacija prikazuje neautentifikovane „Quick“ tunele za lokalni razvoj, a pregled proizvoda navodi HTTP, HTTPS, TCP, SSH i RDP među podržanim objavljenim protokolima.<sup>[[11]](#references)[[12]](#references)</sup> Za razliku od HTTP(S), objavljenim TCP, SSH i RDP rutama nije moguće direktno pristupiti pomoću standardnog klijenta: Cloudflare zahteva `cloudflared` na klijentu koji se povezuje, pa ove rute ne ispunjavaju uslov ove stranice da za raw TCP nije potrebna instalacija klijenta.<sup>[[24]](#references)</sup>

Za imenovani tunel kojim se upravlja lokalno, Cloudflare dokumentuje tok rada `tunnel login`, `create`, `route dns` i `--config ... run ...`.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```

Named tunnels mogu da definišu više ingress pravila u YAML-u; Cloudflare Access policies mogu da kontrolišu pristup objavljenim aplikacijama, a Cloudflare dokumentuje načine za pokretanje konektora kao service i Docker deployment. Quick Tunnels su anonimni, privremeni tuneli za testiranje, sa ograničenjem od 200 istovremenih zahteva i bez podrške za Server-Sent Events (SSE).<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

Aktuelni CLI za Tailscale koristi Serve za deljenje dostupno samo tailnet-u, a Funnel za javno deljenje. Komande podržavaju HTTP/HTTPS reverse-proxy ciljeve i TCP prosleđivanje; Funnel-ov sirovi TCP režim ograničen je na portove 443, 8443 i 10000.<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```

Koristite `--bg` da biste sačuvali konfiguraciju bez pokretanja procesa u prvom planu, a `tailscale funnel status` da biste proverili koje su usluge dostupne sa javnog interneta. Za HTTPS Funnel odredišta, Tailscale dokumentuje terminaciju TLS-a na lokalnom čvoru pre prosleđivanja zahteva lokalnoj usluzi.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp` je opcija koju sami hostujete, pri čemu vi kontrolišete rendezvous server (`frps`) i klijent (`frpc`); njegova dokumentacija obuhvata prosleđivanje lokalnih usluga iza NAT-a ili firewall-a, koristeći determinističke udaljene portove/domene.<sup>[[20]](#references)</sup>

<details>
<summary>Primer konfiguracije frps/frpc</summary>

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

Trenutna dokumentacija projekta obuhvata QUIC transport, token/OIDC autentifikaciju, ograničenja propusnog opsega, provere ispravnosti i Go-template mapiranja opsega — pre korišćenja bilo koje od tih opcija proverite izdanje koje odgovara vašoj implementaciji.<sup>[[20]](#references)</sup>

## Pinggy (zasnovan na SSH-u)

Pinggy dokumentuje SSH prosleđivanje portova unazad preko porta 443, pa može da radi u mrežama u kojima je odlazni SSH sa porta 22 blokiran. Njegov besplatni paket ističe nakon 60 minuta i pri ponovnom povezivanju koristi novi URL, dok Pro nudi trajne tunele i prilagođene domene.<sup>[[21]](#references)[[22]](#references)</sup>

```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```

Možete da zatražite prilagođene domene i trajne tunele na Pro.<sup>[[22]](#references)</sup> Privremene tunele možete automatski ponovo da pokrećete tako što ćete komandu staviti u petlju.

## Napomene o threat intel-u i OPSEC-u

Napadači su zloupotrebljavali ephemeral tunneling, uključujući Cloudflare-ove neautentifikovane `trycloudflare.com` endpoint-e, za isporuku Remote Access Trojans-a putem privremene infrastrukture. Proofpoint je prijavio aktivnost prvi put uočenu u februaru 2024. koja je uključivala Xworm, AsyncRAT, VenomRAT, GuLoader i Remcos, i napomenuo da privremeni tuneli otežavaju odbranu koja se oslanja na statičke blocklist-e.<sup>[[23]](#references)</sup> Razmotrite proaktivnu rotaciju tunela i domena i nadgledajte karakteristične eksterne DNS upite ka tunneler-u koji koristite, kako biste ranije uočili pokušaje blue-team detekcije ili blokiranja infrastrukture.

## References

- [1] [Serveo dokumentacija](https://serveo.net/docs/)
- [2] [SocketXP dokumentacija - Početak rada](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [ngrok Agent interfejs komandne linije](https://ngrok.com/docs/agent/cli)
- [4] [ngrok FAQ](https://ngrok.com/docs/faq)
- [5] [Telebit.js pomoć za zastareli CLI](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [LocalXpose dokumentacija](https://localxpose.gitbook.io/docs)
- [8] [Expose - Deljenje sajtova](https://expose.dev/docs/client/sharing)
- [9] [Expose - Deljenje TCP portova](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [Localtunnel/localtunnel repozitorijum](https://github.com/localtunnel/localtunnel)
- [11] [Cloudflare dokumentacija - Podešavanje Cloudflare Tunnel-a](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Pregled Cloudflare Tunnel-a](https://developers.cloudflare.com/tunnel/)
- [13] [Cloudflare dokumentacija - Korisne komande za tunel](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Cloudflare dokumentacija - Rutiranje](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Cloudflare dokumentacija - Konfiguraciona datoteka](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Cloudflare Access politike](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Cloudflare dokumentacija - Parametri pokretanja](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Tailscale Serve komanda](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Tailscale Funnel komanda](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [fatedier/frp - Fast Reverse Proxy repozitorijum](https://github.com/fatedier/frp)
- [21] [Pinggy dokumentacija - Upotreba](https://pinggy.io/docs/usages/)
- [22] [Pinggy - Jednostavni localhost tuneli](https://pinggy.io/)
- [23] [Proofpoint - Akter pretnje zloupotrebljava Cloudflare Tunnels za isporuku RAT-ova](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
- [24] [Cloudflare dokumentacija - Rutiranje tunela i podržani protokoli](https://developers.cloudflare.com/tunnel/concepts/routing/)
{{#include ../banners/hacktricks-training.md}}
