# Izlaganje lokalnog sadržaja internetu

{{#include ../../banners/hacktricks-training.md}}

**Cilj ove stranice je da predloži alternative koje omogućavaju da se NAJMANJE izlože lokalni sirovi TCP portovi i lokalni webovi (HTTP) internetu, BEZ potrebe za instaliranjem bilo čega na drugom serveru (samo lokalno, ako je potrebno).**

## **Serveo**

Serveo dokumentacija opisuje SSH forwarding za HTTP endpoint-e i privatni/javni TCP forwarding; zahtev za javnim TCP portom koji nije 80/443 (uključujući port 0 za nasumični port) zahteva registrovanog korisnika.<sup>[[1]](#references)</sup>
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

SocketXP vodič za početak rada opisuje `socketxp connect tcp://localhost:22` i `socketxp connect http://localhost:8080` za TCP i HTTP tunele; agent se najpre autentifikuje pomoću portal tokena.<sup>[[2]](#references)</sup>
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

ngrok-ova CLI dokumentacija opisuje HTTP i TCP tunele; njegov FAQ navodi da TCP endpointi besplatnog nivoa zahtevaju važeći način plaćanja i da se kartica ne naplaćuje.<sup>[[3]](#references)[[4]](#references)</sup>
```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```
## Telebit

Nasleđeni Telebit.js CLI help dokumentuje `telebit http <port>` za HTTPS prosleđivanje i `telebit tcp <local> [remote]` za sirovi TCP; dostupnost zavisi od deploymenta i relay-a.<sup>[[5]](#references)</sup>
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Trenutni sajt LocalXpose dokumentuje `loclx tunnel http --to 3000`, navodi podršku za HTTP/TLS/TCP/UDP i kaže da free plan obuhvata ličnu i laku komercijalnu upotrebu, dok je TCP tunneling mogućnost dostupna u plaćenim planovima.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```
## Expose

Expose omogućava `expose share` za lokalne HTTP/HTTPS URL-ove i `share-port` komandu dostupnu samo u PRO verziji za TCP portove.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```
## Localtunnel

Zvanični localtunnel repository opisuje izlaganje localhost-a za testiranje i dokumentuje NPX komandu u nastavku.<sup>[[10]](#references)</sup>
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Aktuelna Cloudflare dokumentacija prikazuje neautentifikovane "Quick" tunnel-e za lokalni development, a pregled proizvoda navodi HTTP, HTTPS, TCP, SSH i RDP među podržanim objavljenim protokolima.<sup>[[11]](#references)[[12]](#references)</sup>

Za lokalno upravljani imenovani tunnel, Cloudflare dokumentuje workflow `tunnel login`, `create`, `route dns` i `--config ... run ...`.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```
Named tunnels mogu definisati više ingress pravila u YAML-u; Cloudflare Access policies mogu kontrolisati pristup objavljenim aplikacijama, a Cloudflare dokumentuje service i Docker deployment putanje za pokretanje connectora. Quick Tunnels su anonimni, privremeni testing tuneli sa ograničenjem od 200 istovremenih zahteva i bez podrške za Server-Sent Events (SSE).<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

Trenutni Tailscale CLI koristi Serve za deljenje samo unutar tailnet-a, a Funnel za javno deljenje. Komande podržavaju HTTP/HTTPS reverse-proxy targete i TCP forwarding; raw TCP mode u Funnel-u ograničen je na portove 443, 8443 i 10000.<sup>[[18]](#references)[[19]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Koristite `--bg` da biste sačuvali konfiguraciju bez održavanja foreground procesa, a koristite `tailscale funnel status` da biste proverili kojim servisima se može pristupiti sa javnog interneta. Za HTTPS Funnel ciljeve, Tailscale dokumentuje TLS termination na lokalnom nodu pre prosleđivanja zahteva lokalnom servisu.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp` je self-hosted opcija kod koje kontrolišete rendezvous server (`frps`) i klijent (`frpc`); njegova dokumentacija obuhvata prosleđivanje lokalnih servisa koji se nalaze iza NAT-a ili firewall-a, uz determinističke udaljene portove/domene.<sup>[[20]](#references)</sup>

<details>
<summary>Primer frps/frpc konfiguracije</summary>
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

Trenutna dokumentacija projekta uključuje QUIC transport, token/OIDC autentifikaciju, ograničenja bandwidth-a, health check-ove i Go-template range mapiranja — pre korišćenja bilo koje od tih opcija konsultujte release koji odgovara vašem deployment-u.<sup>[[20]](#references)</sup>

## Pinggy (SSH-based)

Pinggy dokumentuje SSH reverse forwarding preko porta 443, pa može raditi na mrežama na kojima je outbound SSH preko porta 22 blokiran. Njegov free plan ističe nakon 60 minuta i koristi novi URL nakon ponovnog povezivanja, dok Pro dodaje persistent tunnels i custom domains.<sup>[[21]](#references)[[22]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```
Možete zatražiti prilagođene domene i persistent tunnels na Pro.<sup>[[22]](#references)</sup> Privremene tunnels možete automatski reciklirati tako što ćete komandu obaviti petljom.

## Threat intel & OPSEC beleške

Adversaries su zloupotrebljavali ephemeral tunneling, uključujući Cloudflare-ove neautentifikovane `trycloudflare.com` endpoints, za isporuku Remote Access Trojans preko privremene infrastrukture. Proofpoint je prijavio aktivnost prvi put uočenu u februaru 2024. koja je uključivala Xworm, AsyncRAT, VenomRAT, GuLoader i Remcos, i naveo da privremeni tunnels otežavaju odbranu koja se oslanja na statičke blocklists.<sup>[[23]](#references)</sup> Razmotrite proaktivno rotiranje tunnels i domena i nadgledajte karakteristične spoljne DNS upite ka tunneleru koji koristite, kako biste rano uočili blue-team detekciju ili pokušaje blokiranja infrastrukture.

## References

- [1] [Serveo Documentation](https://serveo.net/docs/)
- [2] [SocketXP Documentation - Početak rada](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [ngrok Agent Command Line Interface](https://ngrok.com/docs/agent/cli)
- [4] [ngrok FAQ](https://ngrok.com/docs/faq)
- [5] [Telebit.js legacy CLI help](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [LocalXpose Documentation](https://localxpose.gitbook.io/docs)
- [8] [Expose - Deljenje sajtova](https://expose.dev/docs/client/sharing)
- [9] [Expose - Deljenje TCP portova](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [localtunnel/localtunnel repository](https://github.com/localtunnel/localtunnel)
- [11] [Cloudflare Docs - Podešavanje Cloudflare Tunnel-a](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Cloudflare Tunnel overview](https://developers.cloudflare.com/tunnel/)
- [13] [Cloudflare Docs - Korisne tunnel komande](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Cloudflare Docs - Routing](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Cloudflare Docs - Configuration file](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Cloudflare Access policies](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Cloudflare Docs - Run parameters](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Tailscale Serve command](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Tailscale Funnel command](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [fatedier/frp - Fast Reverse Proxy repository](https://github.com/fatedier/frp)
- [21] [Pinggy Documentation - Usage](https://pinggy.io/docs/usages/)
- [22] [Pinggy - Simple Localhost Tunnels](https://pinggy.io/)
- [23] [Proofpoint - Threat Actor Abuses Cloudflare Tunnels to Deliver RATs](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
{{#include ../../banners/hacktricks-training.md}}
