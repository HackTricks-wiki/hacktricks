# Izlaganje lokalnih servisa internetu

{{#include ../../banners/hacktricks-training.md}}

**Cilj ove stranice je da predloži alternative koje omogućavaju NAJMANJE izlaganje lokalnih raw TCP portova i lokalnih web aplikacija (HTTP) internetu, BEZ potrebe za instaliranjem bilo čega na drugom serveru (samo lokalno, ako je potrebno).**

## **Serveo**

Sa [https://serveo.net/](https://serveo.net/) dostupno je nekoliko funkcija za http i prosleđivanje portova **besplatno**.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Sa [https://www.socketxp.com/download](https://www.socketxp.com/download), omogućava izlaganje tcp i http usluga:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

Sa [https://ngrok.com/](https://ngrok.com/), moguće je izložiti http i tcp portove:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

Sa [https://telebit.cloud/](https://telebit.cloud/) omogućava izlaganje http i tcp portova:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Sa [https://localxpose.io/](https://localxpose.io/) dostupno je nekoliko funkcija za http i prosleđivanje portova **besplatno**.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

Sa [https://expose.dev/](https://expose.dev/) omogućava izlaganje http i tcp portova:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

Sa [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) možete besplatno izložiti http:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Cloudflare-ov `cloudflared` CLI može da kreira neautentifikovane „Quick“ tunnel-e za brze demonstracije ili imenovane tunnel-e povezane sa vašim domenom/hostname-ovima. Podržava HTTP(S) reverse proxy-je, kao i raw TCP mapiranja rutirana kroz Cloudflare edge.<sup>[[1]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
Named tunnels vam omogućavaju da definišete više ingress pravila (HTTP, SSH, RDP itd.) unutar `tunnel.yml`, podržavaju access policy-je po servisu putem Cloudflare Access-a i mogu da rade kao systemd kontejneri radi perzistencije. Quick Tunnels su anonimni i privremeni — odlični za pripremu phishing payload-a ili testiranje webhook-a, ali Cloudflare ne garantuje dostupnost.<sup>[[1]](#references)</sup>

## Tailscale Funnel / Serve

Tailscale v1.52+ isporučuje objedinjene tokove rada `tailscale serve` (deljenje unutar tailnet-a) i `tailscale funnel` (objavljivanje na širem internetu). Obe komande mogu da rade reverse proxy za HTTP(S) ili da prosleđuju sirovi TCP, uz automatski TLS i kratke `*.ts.net` hostname-ove.<sup>[[3]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Koristite `--bg` da sačuvate konfiguraciju bez zadržavanja procesa u foreground-u, a `tailscale funnel status` da proverite kojim servisima se može pristupiti sa javnog interneta. Pošto Funnel završava TLS na lokalnom čvoru, svi upiti za akreditive, header-i ili primena mTLS-a mogu ostati pod vašom kontrolom.

## Fast Reverse Proxy (frp)

`frp` je self-hosted opcija kod koje kontrolišete rendezvous server (`frps`) i klijent (`frpc`). Odličan je za red teamove koji već poseduju VPS i žele predvidljive domene/portove.

<details>
<summary>Primer frps/frpc konfiguracije</summary>
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

Novija izdanja dodaju QUIC transport, token/OIDC auth, ograničenja propusnog opsega, health checks i mapiranja opsega zasnovana na Go template-ima — korisno za brzo pokretanje više listenera koji se vraćaju do implantata na različitim hostovima.<sup>[[4]](#references)</sup>

## Pinggy (zasnovan na SSH-u)

Pinggy pruža SSH-accessible tunele preko TCP/443, tako da radi čak i iza captive proxy-ja koji dozvoljavaju samo HTTPS. Sesije traju 60 minuta na free tier-u i mogu se skriptovati za brze demonstracije ili webhook relay-e.<sup>[[5]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
Možete zahtevati custom domene i duže-lived tunnel-e na plaćenom planu ili automatski reciklirati tunnel-e tako što ćete komandu staviti u loop.

## Napomene o threat intel-u i OPSEC-u

Napadači sve više zloupotrebljavaju ephemeral tunneling (naročito Cloudflare-ove neautentifikovane `trycloudflare.com` endpoint-e) za postavljanje Remote Access Trojan payload-a i skrivanje C2 infrastrukture. Proofpoint je pratio kampanje od februara 2024. godine koje su distribuirale AsyncRAT, Xworm, VenomRAT, GuLoader i Remcos tako što su download stage-ove usmeravale na kratkotrajne TryCloudflare URL-ove, čime su tradicionalne statičke blockliste postale znatno manje efikasne. Razmotrite proaktivnu rotaciju tunnel-a i domena, ali takođe pratite karakteristične eksterne DNS upite ka tunneler-u koji koristite, kako biste rano uočili blue-team detekciju ili pokušaje blokiranja infrastrukture.<sup>[[2]](#references)</sup>

## Reference

- [1] [Cloudflare Docs - Create a locally-managed tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [2] [Proofpoint - Threat Actor Abuses Cloudflare Tunnels to Deliver RATs](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
- [3] [Tailscale - Reintroducing Serve and Funnel](https://tailscale.com/blog/reintroducing-serve-funnel)
- [4] [fatedier/frp - Fast Reverse Proxy repository](https://github.com/fatedier/frp)
- [5] [Pinggy Documentation - Usage](https://pinggy.io/docs/usages/)

{{#include ../../banners/hacktricks-training.md}}
